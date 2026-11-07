"""String extraction and lightweight classification.

Strings are pulled straight out of the file bytes (ASCII and UTF-16LE) and then
bucketed by what they look like: URLs, IPs, registry paths, credentials, shell
commands and so on. Nothing is resolved or fetched; this is pattern matching on
literal bytes.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

MAX_STRINGS = 200_000
MAX_TEXT_LEN = 4096


@dataclass(frozen=True)
class StringHit:
    text: str
    kind: str          # "ascii" | "utf16"
    region: str        # section name, "<headers>" or "<overlay>"
    offset: int


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    name: str


def build_regions(pe) -> list[Region]:
    regions: list[Region] = [Region(0, min(len(pe.data), pe.size_of_headers or 0), "<headers>")]
    for sec in pe.sections:
        if sec.raw_size and sec.raw_ptr < len(pe.data):
            regions.append(Region(sec.raw_ptr, min(sec.raw_ptr + sec.raw_size, len(pe.data)),
                                  sec.name))
    overlay_start, overlay_size = pe.overlay()
    if overlay_size > 0:
        regions.append(Region(overlay_start, overlay_start + overlay_size, "<overlay>"))
    regions.sort(key=lambda r: r.start)
    return regions


def region_for(regions: list[Region], offset: int) -> str:
    lo, hi = 0, len(regions) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        r = regions[mid]
        if offset < r.start:
            hi = mid - 1
        elif offset >= r.end:
            lo = mid + 1
        else:
            return r.name
    return "<unknown>"


def extract_strings(pe, min_len: int = 4) -> tuple[list[StringHit], bool]:
    """Return (hits, truncated). Duplicate texts are kept once, with counts
    collapsed later by the caller through Counter."""
    data = pe.data
    regions = build_regions(pe)
    hits: list[StringHit] = []
    truncated = False

    for match in ASCII_RE.finditer(data):
        raw = match.group()
        if len(raw) < min_len:
            continue
        text = raw.decode("ascii", "replace")
        hits.append(StringHit(text, "ascii", region_for(regions, match.start()), match.start()))
        if len(hits) >= MAX_STRINGS:
            truncated = True
            break

    if not truncated:
        for match in UTF16_RE.finditer(data):
            raw = match.group()
            text = raw.decode("utf-16-le", "replace")
            if len(text) < min_len:
                continue
            hits.append(StringHit(text, "utf16", region_for(regions, match.start()), match.start()))
            if len(hits) >= MAX_STRINGS:
                truncated = True
                break

    return hits, truncated


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})(?::\d{1,5})?(?![\d.])")
_URL_RE = re.compile(
    r"(?i)\b(?:https?|ftps?|wss?|tcp|udp|socks[45]|smb|ldap)://"
    r"[^\s\"'<>{}|\\^`\x00]{3,300}")
_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|io|co|ru|cn|su|top|xyz|online|site|club|onion|"
    r"me|tv|cc|shop|app|dev|cloud|link|pw|ws)\b")
_EMAIL_RE = re.compile(r"[\w.+-]{2,64}@[\w-]{2,63}(?:\.[\w-]{2,24})+")
_REGISTRY_RE = re.compile(
    r"(?i)(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)"
    r"(?:\\[^\s\"']{1,240})?"
    r"|\\\\(?:Software|SYSTEM)\\CurrentControlSet\\[^\s\"']{1,240}")
_ENV_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]{1,30}%")
_PATH_RE = re.compile(
    r"(?i)(?:^|[\s\"'=,(])(?:[A-Z]:\\|\\\\[A-Za-z0-9._$-]{1,64}\\)"
    r"[^\s\"'<>|*?,]{1,240}")
_UA_RE = re.compile(
    r"(?i)(?:Mozilla/\d\.\d|User-Agent:|curl/\d|Wget/\d|python-requests/|"
    r"Go-http-client|okhttp/|Dalvik/|WinHTTP)")
_CRED_RE = re.compile(
    r"(?i)(?:\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*\S{4,120}"
    r"|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"
    r"|\bbearer\s+[A-Za-z0-9._-]{16,})")
_SQL_RE = re.compile(
    r"(?i)\b(?:select\s+[\w*,.\s]{1,80}\s+from\s+\w+|insert\s+into\s+\w+|"
    r"update\s+\w+\s+set\s|delete\s+from\s+\w+|drop\s+table\s+\w+)")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{64,}={0,2}$")
_WALLET_RE = re.compile(
    r"\b(?:bc1[a-z0-9]{25,60}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_TOOLING_RE = re.compile(
    r"(?i)(?:"
    # Unambiguous brand/module tokens. \b stops "xmimikatz" and "mimikatzfoo";
    # none of these words mean anything else in software.
    r"\b(?:mimikatz|meterpreter|cobaltstrike|sekurlsa|msfvenom|psexec|ngrok)\b"
    # Image and module names, with a guard so "beacon.dll.mui" (a resource of the
    # same name) does not count as the real thing.
    r"|\bbeacon\.dll(?!\.)"
    r"|\blsass\.exe\b"
    # Narrowed on purpose: bare "reflective" is ordinary English and matched
    # prose, while the old \breflective\b could never match "ReflectiveLoader"
    # (the \b fails between "e" and "L"). The compounds below catch the real
    # artefacts and drop the adjective.
    r"|\breflective[ _-]?(?:loader|load|dll|injection|loadlibrary)\b"
    r"|\bshellcode\b"
    # "meterp" alone is a prefix of "parameter": para-meterp-rocessor. The
    # executable name is the only thing worth matching.
    r"|\bmeterp(?:reter)?\.exe\b"
    # "chisel" is also a woodworking word; the released artefacts are these.
    r"|\bchisel(?:\.exe|_(?:windows|linux|darwin|arm|386|amd64))"
    # frp[A-Z]?\.exe under re.I matched "frpx.exe"; the tunnel binaries are frp/frpc/frps.
    r"|\bfrp[cs]?\.exe\b"
    # Same webhook/paste rules as _EXFIL_RE: host-shaped, whole-token guarded.
    r"|(?<![\w-])(?:discord|discordapp|ptb\.discord|canary\.discord)\.com/api/webhooks(?![\w-])"
    r"|(?<![\w-])api\.telegram\.org/bot"
    r"|(?<![\w-])pastebin\.com/raw(?![\w-])"
    # A hidden service needs a label in front of the TLD.
    r"|(?<=[\w-])\.onion\b"
    r")")
_SWITCH_RE = re.compile(r"(?:^|\s)(?:-[A-Za-z]{1,3}|--[a-z][\w-]{1,20})(?=\s|$)")
# Every alternative here is a *hostname*, not a word that happens to appear in
# one: "requestbin" used to match DefaultUser::RequestBin-dingInfo and "termbin"
# would match any "...TermBin..." identifier. The guards are:
#   (?<![\w-])  nothing word-like or hyphen-joined directly before the host
#               (a "." is allowed, so subdomained hosts such as
#               <id>.m.pipedream.net still match);
#   (?![\w-])   the host ends here: "gofile.io.evil.tld" is another host;
#   (?!\.\w)    ...but a trailing dot ("uploaded to 0x0.st.") is just punctuation.
_EXFIL_RE = re.compile(
    r"(?i)(?:"
    # Hosted relays where the *path* is the payload drop.
    r"(?<![\w-])(?:discord|discordapp|ptb\.discord|canary\.discord)\.com/api/webhooks(?![\w-])"
    r"|(?<![\w-])api\.telegram\.org/bot"
    r"|(?<![\w-])hooks\.slack\.com(?![\w-])(?!\.\w)"
    # Paste / file-drop collectors, each with its own TLD.
    r"|(?<![\w-])webhook\.site(?![\w-])(?!\.\w)"
    r"|(?<![\w-])requestbin\.(?:com|net|io)(?![\w-])(?!\.\w)"
    r"|(?<![\w-])pipedream\.net(?![\w-])(?!\.\w)"
    r"|(?<![\w-])transfer\.sh(?![\w-])(?!\.\w)"
    r"|(?<![\w-])anonfiles\.com(?![\w-])(?!\.\w)"
    r"|(?<![\w-])gofile\.io(?![\w-])(?!\.\w)"
    r"|(?<![\w-])0x0\.st(?![\w-])(?!\.\w)"
    r"|(?<![\w-])termbin\.com(?![\w-])(?!\.\w)"
    r")")

CATEGORY_TITLES = {
    "url": "URLs / endpoints",
    "ip": "IP addresses",
    "domain": "domains",
    "email": "e-mail addresses",
    "registry": "registry paths",
    "env": "environment variables",
    "path": "file paths",
    "user-agent": "User-Agent / HTTP client",
    "credential": "credential-shaped strings",
    "sql": "SQL statements",
    "base64": "base64-looking blobs",
    "wallet": "crypto wallet addresses",
    "tooling": "offensive-tooling / exfil markers",
    "command": "command-line-ish strings",
    "exfil": "exfiltration endpoints",
}

CATEGORY_ORDER = list(CATEGORY_TITLES)


def _valid_ipv4(text: str) -> bool:
    host = text.split(":", 1)[0]
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def classify(texts: Iterable[str]) -> dict[str, Counter]:
    buckets: dict[str, Counter] = {name: Counter() for name in CATEGORY_TITLES}

    for text in texts:
        if len(text) < 5 or len(text) > MAX_TEXT_LEN:
            continue
        matched_any = False

        url_match = _URL_RE.search(text)
        if url_match:
            buckets["url"][url_match.group().rstrip(".,;)}]")] += 1
            matched_any = True

        for ip_match in _IPV4_RE.finditer(text):
            value = ip_match.group()
            if not _valid_ipv4(value):
                continue
            # "5.1.0.0" and friends are version numbers, not hosts.
            if value.endswith(".0") and ":" not in value:
                continue
            buckets["ip"][value] += 1
            matched_any = True

        if "://" not in text:
            for domain_match in _DOMAIN_RE.finditer(text):
                buckets["domain"][domain_match.group().lower()] += 1
                matched_any = True

        if "@" in text:
            m = _EMAIL_RE.search(text)
            if m:
                buckets["email"][m.group()] += 1
                matched_any = True

        m = _REGISTRY_RE.search(text)
        if m:
            buckets["registry"][m.group().strip()] += 1
            matched_any = True

        if "%" in text:
            for m in _ENV_RE.finditer(text):
                buckets["env"][m.group()] += 1
                matched_any = True

        if "\\" in text or "/" in text:
            m = _PATH_RE.search(text)
            if m:
                buckets["path"][m.group().strip()] += 1
                matched_any = True

        m = _UA_RE.search(text)
        if m:
            buckets["user-agent"][text[:160]] += 1
            matched_any = True

        m = _CRED_RE.search(text)
        if m:
            buckets["credential"][_redact(m.group())] += 1
            matched_any = True

        m = _SQL_RE.search(text)
        if m:
            buckets["sql"][text[:160]] += 1
            matched_any = True

        if len(text) >= 64 and _B64_RE.match(text):
            buckets["base64"][text[:80] + ("…" if len(text) > 80 else "")] += 1
            matched_any = True

        m = _WALLET_RE.search(text)
        if m:
            buckets["wallet"][m.group()] += 1
            matched_any = True

        m = _TOOLING_RE.search(text)
        if m:
            buckets["tooling"][text[:160]] += 1

        m = _EXFIL_RE.search(text)
        if m:
            buckets["exfil"][text[:160]] += 1

        if not matched_any and 8 <= len(text) <= 300:
            switches = _SWITCH_RE.findall(text)
            if len(switches) >= 2:
                buckets["command"][text.strip()] += 1

    return {k: v for k, v in buckets.items() if v}


def _redact(text: str) -> str:
    """Keep the shape of a credential-looking string but drop the secret part."""
    if "=" in text:
        head, _, tail = text.partition("=")
        return f"{head.strip()}=<{len(tail.strip())} chars>"
    if ":" in text:
        head, _, tail = text.partition(":")
        return f"{head.strip()}:<{len(tail.strip())} chars>"
    return f"<{len(text)} chars redacted>"
