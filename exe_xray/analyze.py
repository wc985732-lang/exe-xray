"""Static analysis pipeline: file -> evidence -> verdict.

Hard rule enforced by construction: this module opens the target file exactly
once, in binary read mode, and never hands the bytes to anything that executes
them. No subprocess, no ctypes, no shell.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import VERSION
from .authenticode import inspect_signature
from .capabilities import CATEGORY_INFO, category_score, classify_libraries
from .pe import PEError, PE
from .strings import (CATEGORY_ORDER, CATEGORY_TITLES, classify, extract_strings)

RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
    7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
    12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
    19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML",
    24: "MANIFEST",
}

PACKER_SECTION_MARKERS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", "upx!": "UPX",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".aspack": "ASPack", ".adata": "ASPack", ".asdata": "ASPack",
    ".packed": "generic packer", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".petite": "Petite", ".pklstb": "PKLite", ".boom": "The Boomerang",
    ".ccg": "CCG packer", ".perplex": "Perplex", ".rmnet": "Ramnit",
    ".seau": "SeauSFX", ".taz": "PESpin", ".y0da": "Y0da", ".z": "Z-protector",
    ".svkp": "SVKP", ".spack": "Simple packer", ".sforce": "StarForce",
    ".mpress": "MPRESS", ".neolite": "NeoLite", ".neolit": "NeoLite",
    ".upx": "UPX", ".crypt": "cryptor", ".enc": "cryptor",
}

SUSPICIOUS_IMPORT_TOTAL = 12

# Positive evidence is evidence too. A cryptographically verified signature and a
# stock Microsoft component location are reasons *not* to shout, so they come off
# the score instead of being printed and ignored.
SIGNATURE_CREDIT = 35
WINDOWS_COMPONENT_CREDIT = 20
WINDOWS_COMPONENT_DIRS = ("system32", "syswow64", "winsxs")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _iso(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _hex(value: int) -> str:
    return f"0x{value:x}"


class AnalysisError(Exception):
    """User-facing failure: file missing, unreadable, or not a PE."""


# --------------------------------------------------------------------------- #
# main entry
# --------------------------------------------------------------------------- #

def analyze(path: str, *, max_strings: int = 4000, min_string_len: int = 4,
            max_file_mb: int = 512, skip_strings: bool = False) -> dict[str, Any]:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise AnalysisError(f"no such file: {path}")
    if os.path.isdir(path):
        raise AnalysisError(f"path is a directory, not a file: {path}")
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise AnalysisError(f"cannot stat file: {exc}") from exc
    if size == 0:
        raise AnalysisError("file is empty")
    if size > max_file_mb * 1024 * 1024:
        raise AnalysisError(
            f"file is {size / 1048576:.1f} MiB, above the {max_file_mb} MiB limit "
            f"(raise it with --max-file-mb)")

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise AnalysisError(f"cannot read file: {exc}") from exc

    if len(data) < 2 or data[:2] != b"MZ":
        head = data[:16].hex(" ")
        raise AnalysisError(
            f"not a Windows executable: missing 'MZ' signature (first bytes: {head})")

    try:
        pe = PE(data, path)
    except PEError as exc:
        raise AnalysisError(f"PE parsing failed: {exc}") from exc

    report: dict[str, Any] = {
        "tool": {"name": "exe-xray", "version": VERSION},
        "file": _file_facts(path, data, size),
        "pe": _pe_facts(pe),
        "signature": _safe(lambda: inspect_signature(pe), {"status": "error"}),
        "imports": _import_facts(pe),
        "strings": ({"total": 0, "unique": 0, "truncated": False, "by_category": {},
                     "skipped": True} if skip_strings
                    else _string_facts(pe, max_strings, min_string_len)),
    }

    # cross-cutting judgements
    report["packing"] = _packing_verdict(pe, report["pe"]["sections"], report["imports"])
    report["risk"] = _risk(report)
    report["verdict"] = _verdict(report, pe)
    return report


def _safe(fn, default):
    try:
        return fn()
    except Exception as exc:  # defensive: one broken facet must not kill the report
        out = dict(default) if isinstance(default, dict) else {}
        out.setdefault("error", f"{type(exc).__name__}: {exc}")
        return out


# --------------------------------------------------------------------------- #
# file
# --------------------------------------------------------------------------- #

def _file_facts(path: str, data: bytes, size: int) -> dict[str, Any]:
    stat = os.stat(path)
    return {
        "path": path,
        "name": os.path.basename(path),
        "size": size,
        "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%SZ"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


# --------------------------------------------------------------------------- #
# PE facts
# --------------------------------------------------------------------------- #

def _pe_facts(pe: PE) -> dict[str, Any]:
    sections = []
    for sec in pe.sections:
        raw = pe.data[sec.raw_ptr: sec.raw_ptr + sec.raw_size] if sec.raw_size else b""
        sections.append({
            "name": sec.name,
            "virtual_address": _hex(sec.virtual_address),
            "virtual_size": sec.virtual_size,
            "raw_size": sec.raw_size,
            "raw_offset": _hex(sec.raw_ptr),
            "flags": sec.flags,
            "entropy": round(entropy(raw), 3),
        })

    stored = pe.checksum
    computed = pe.computed_checksum()
    dotnet = _safe(pe.dotnet, None)
    debug = _safe(pe.debug_entries, [])
    pdb = ""
    guid = ""
    for entry in debug or []:
        if entry.get("pdb"):
            pdb = entry["pdb"]
            guid = entry.get("guid", "")
            break

    resources = _safe(pe.resources, [])
    type_counts: Counter = Counter()
    for res in resources or []:
        path = res.get("path") or []
        if path:
            type_counts[RESOURCE_TYPES.get(path[0], str(path[0]))] += 1

    version = _safe(pe.version_info, {}) or {}
    manifest = _manifest_info(pe, resources or [])

    exports = _safe(pe.exports, [])
    overlay_off, overlay_size = pe.overlay()

    return {
        "format": "PE32+" if pe.is_pe32plus else "PE32",
        "machine": pe.arch,
        "bits": pe.bits,
        "kind": "DLL" if pe.is_dll else "EXE",
        "subsystem": pe.subsystem_name,
        "subsystem_id": pe.subsystem,
        "linker": f"{pe.linker_major}.{pe.linker_minor}",
        "timestamp": pe.timestamp,
        "timestamp_iso": _iso(pe.timestamp),
        "timestamp_note": _timestamp_note(pe.timestamp),
        "entry_point": _hex(pe.entry_point),
        "image_base": _hex(pe.image_base),
        "image_size": pe.size_of_image,
        "checksum": {
            "stored": _hex(stored),
            "computed": _hex(computed),
            "valid": stored == computed,
        },
        "dll_characteristics": pe.dll_flags,
        "file_characteristics": pe.file_flags,
        "sections": sections,
        "dotnet": dotnet,
        "debug": {"pdb": pdb, "guid": guid},
        "rich": _safe(pe.rich_header, {}),
        "overlay": {"offset": overlay_off, "size": overlay_size},
        "resources": {
            "types": dict(sorted(type_counts.items())),
            "count": len(resources or []),
            "version": version,
            "manifest": manifest,
        },
        "exports": {
            "count": len(exports or []),
            "sample": [e.name for e in (exports or [])[:12]],
            "forwarders": [e.name for e in (exports or []) if e.forwarder][:12],
        },
        "warnings": pe.warnings[:20],
    }


def _timestamp_note(ts: int) -> str:
    if ts == 0:
        return "zero (timestamp stripped or reproducible build)"
    if ts > 2_000_000_000:
        return "value is beyond 2033: likely a reproducible-build hash, not a real time"
    if ts < 315_532_800:
        return "before 1980: not a plausible build time"
    return ""


def _manifest_info(pe: PE, resources: list[dict[str, Any]]) -> dict[str, Any]:
    for res in resources:
        path = res.get("path") or []
        if not path or path[0] != 24:  # RT_MANIFEST
            continue
        off = pe.rva_to_offset_safe(res.get("rva", 0))
        if off is None:
            continue
        blob = pe.data[off: off + min(res.get("size", 0), 65536)]
        text = blob.decode("utf-8", "replace")
        info: dict[str, Any] = {"present": True}
        m = re.search(r"requestedExecutionLevel[^>]*?level\s*=\s*[\"']([^\"']+)[\"']", text)
        if m:
            info["execution_level"] = m.group(1)
        if "uiAccess=\"true\"" in text or "uiAccess='true'" in text:
            info["ui_access"] = True
        if "supportedOS" in text:
            info["supports_compat_layers"] = True
        return info
    return {"present": False}


# --------------------------------------------------------------------------- #
# imports
# --------------------------------------------------------------------------- #

def _import_facts(pe: PE) -> dict[str, Any]:
    imports = _safe(pe.imports, [])
    delay = _safe(pe.delay_imports, [])
    classified = classify_libraries(imports)

    dlls = [{"name": lib.name, "functions": len(lib.functions), "delay": False}
            for lib in imports]
    dlls += [{"name": lib.name, "functions": len(lib.functions), "delay": True}
             for lib in delay]

    categories: dict[str, Any] = {}
    for name, hits in classified["categories"].items():
        phrase, weight = CATEGORY_INFO.get(name, (name, 0))
        uniq: list[dict[str, str]] = []
        seen = set()
        for hit in hits:
            key = (hit["dll"], hit["api"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(hit)
        categories[name] = {
            "phrase": phrase,
            "weight": weight,
            "count": len(uniq),
            "apis": uniq,
        }

    ordered = {k: categories[k] for k in sorted(
        categories, key=lambda c: (-categories[c]["weight"], c))}

    return {
        "dll_count": len(imports) + len(delay),
        "function_count": classified["total"],
        "unclassified": classified["unclassified"],
        "runtime_glue": classified.get("runtime", 0),
        "dlls": sorted(dlls, key=lambda d: (-d["functions"], d["name"].lower())),
        "categories": ordered,
        "delay_imports_used": bool(delay),
    }


# --------------------------------------------------------------------------- #
# strings
# --------------------------------------------------------------------------- #

def _string_facts(pe: PE, max_strings: int, min_len: int) -> dict[str, Any]:
    hits, truncated = extract_strings(pe, min_len=min_len)
    # collapse duplicates, keep the most repeated
    counts: Counter = Counter(h.text for h in hits)
    buckets = classify(counts.keys())

    out: dict[str, Any] = {"total": len(hits), "unique": len(counts),
                           "truncated": truncated, "by_category": {}}
    for name in CATEGORY_ORDER:
        bucket = buckets.get(name)
        if not bucket:
            continue
        top = bucket.most_common(max_strings)
        out["by_category"][name] = {
            "title": CATEGORY_TITLES.get(name, name),
            "count": len(bucket),
            "samples": [{"text": t, "count": c} for t, c in top],
        }
    return out


# --------------------------------------------------------------------------- #
# packing
# --------------------------------------------------------------------------- #

def _packing_verdict(pe: PE, sections: list[dict[str, Any]],
                     imports: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    for sec in sections:
        marker = PACKER_SECTION_MARKERS.get(sec["name"].lower())
        if marker:
            score += 40
            reasons.append(f"section name '{sec['name']}' is the signature of {marker}")

    if b"UPX!" in pe.data[:2_000_000]:
        score += 30
        reasons.append("'UPX!' marker found in the image")

    for sec in sections:
        if sec["raw_size"] >= 4096 and sec["entropy"] > 7.2:
            score += 20
            reasons.append(
                f"section {sec['name']} has entropy {sec['entropy']:.2f} (>7.2 is "
                f"typical for compressed or encrypted code)")
        if "X" in sec["flags"] and "W" in sec["flags"]:
            score += 15
            reasons.append(f"section {sec['name']} is both writable and executable")
        if sec["raw_size"] and sec["virtual_size"] > sec["raw_size"] * 4:
            score += 10
            reasons.append(
                f"section {sec['name']} reserves {sec['virtual_size']} bytes but stores "
                f"only {sec['raw_size']} (self-unpacking stub pattern)")
        if not sec["name"].strip():
            score += 5
            reasons.append("a section has an empty name")

    total_funcs = imports.get("function_count", 0)
    size = len(pe.data)
    if total_funcs and total_funcs < SUSPICIOUS_IMPORT_TOTAL and size > 64 * 1024:
        score += 20
        reasons.append(f"only {total_funcs} imported functions in a {size // 1024} KiB "
                       f"image (packers usually resolve APIs at runtime)")
    if total_funcs == 0 and size > 32 * 1024:
        score += 25
        reasons.append("no import table at all")

    _, overlay = pe.overlay()
    if overlay > size * 0.5 and overlay > 4096:
        score += 10
        reasons.append(f"{overlay // 1024} KiB of overlay data after the last section")

    score = min(score, 100)
    if score >= 60:
        verdict = "likely packed / protected"
    elif score >= 30:
        verdict = "possibly packed"
    else:
        verdict = "no packing indicators"
    return {"score": score, "verdict": verdict, "reasons": reasons[:8]}


# --------------------------------------------------------------------------- #
# risk + verdict
# --------------------------------------------------------------------------- #

def _is_windows_component(report: dict[str, Any]) -> tuple[bool, str]:
    """(is it a stock Windows component, the directory label) from file evidence.

    Both halves are required: the file has to sit under the Windows directory
    *and* carry Microsoft as the version-resource company. Location alone would be
    worthless (anything can be dropped into System32), and the company string
    alone would cover every redistributable.
    """
    path = (report.get("file") or {}).get("path") or ""
    if not path:
        return (False, "")
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    try:
        full = os.path.normcase(os.path.abspath(path))
        base = os.path.normcase(os.path.normpath(root))
    except (OSError, ValueError):
        return (False, "")
    if not full.startswith(base + os.sep):
        return (False, "")
    remainder = full[len(base) + 1:]
    parts = remainder.split(os.sep)
    if len(parts) == 1:
        label = "the Windows directory"
    elif parts[0] in WINDOWS_COMPONENT_DIRS:
        label = os.path.basename(os.path.dirname(full))
    else:
        return (False, "")
    version = (((report.get("pe") or {}).get("resources") or {})
               .get("version") or {})
    strings = version.get("strings") or {}
    company = str(strings.get("CompanyName") or "").lower()
    if "microsoft" not in company:
        return (False, "")
    return (True, label or "the Windows directory")


def _risk(report: dict[str, Any]) -> dict[str, Any]:
    cats = report["imports"]["categories"]
    strings = report["strings"]["by_category"]
    signals: list[dict[str, str]] = []

    def add(sid: str, level: str, text: str) -> None:
        signals.append({"id": sid, "level": level, "text": text})

    score = category_score({k: v["apis"] for k, v in cats.items()})

    if "injection" in cats:
        apis = ", ".join(a["api"] for a in cats["injection"]["apis"][:4])
        add("code-injection", "high",
            f"can write/inject code into another process ({apis})")
        score += 12
    if "memory-read" in cats:
        apis = ", ".join(a["api"] for a in cats["memory-read"]["apis"][:4])
        add("process-memory-read", "note",
            f"reads another process's memory ({apis}): debuggers, crash reporters and "
            f"task managers do this, and it cannot modify or run anything there")
    if "keyboard" in cats and "network" in cats:
        add("keylogger-channel", "high",
            "reads key state and also opens sockets: a keylogger with an exfil path")
        score += 15
    if "keyboard" in cats:
        add("keystroke-reads", "warn",
            "reads keyboard state (" + ", ".join(a["api"] for a in cats["keyboard"]["apis"][:3]) + ")")
    if "hook" in cats:
        add("hooks", "warn", "installs Windows hooks (classic in-process injection vector)")
    if "screen" in cats and ("network" in cats or "http" in cats):
        add("screen-capture", "warn", "captures screen content and has a network path")
    if "download" in cats:
        add("downloader", "high",
            "downloads files from a URL (" + ", ".join(
                a["api"] for a in cats["download"]["apis"][:3]) + ")")
        score += 8
    if "shell-exec" in cats:
        add("shell-exec", "warn",
            "launches commands through the shell (" + ", ".join(
                a["api"] for a in cats["shell-exec"]["apis"][:3]) + ")")
    if "service" in cats:
        add("service", "warn", "talks to the service control manager")
        score += 4
    if "driver" in cats:
        add("driver", "high", "loads or talks to kernel drivers")
        score += 10
    if "anti-debug" in cats:
        add("anti-debug", "note",
            "checks for debuggers/analysis (" + ", ".join(
                a["api"] for a in cats["anti-debug"]["apis"][:3]) + ")")
    if "dpapi" in cats:
        add("dpapi", "warn", "uses DPAPI to seal or unseal secrets")
    if "shadowcopy" in cats:
        add("shadowcopy", "high", "touches volume shadow copies")
    if "privilege" in cats:
        add("privilege", "note", "manipulates tokens or privileges")
    if "netapi" in cats:
        add("netapi", "warn", "enumerates users/shares through the SAM APIs")

    # string-driven
    if "exfil" in strings:
        top = strings["exfil"]["samples"][0]["text"][:90]
        add("exfil-endpoint", "high", f"hard-coded exfiltration endpoint: {top}")
        score += 15
    if "credential" in strings:
        add("credential-strings", "warn",
            f"{strings['credential']['count']} credential-shaped literal(s) in the image")
        score += 8
    if "wallet" in strings:
        add("wallet", "warn", "hard-coded crypto wallet address")
        score += 5
    if "tooling" in strings:
        top = strings["tooling"]["samples"][0]["text"][:90]
        add("tooling", "high", f"offensive-tooling marker in strings: {top}")
        score += 12
    if "registry" in strings:
        run_like = [s["text"] for s in strings["registry"]["samples"]
                    if "run" in s["text"].lower() and "currentversion" in s["text"].lower()]
        if run_like:
            add("autostart", "warn", f"autostart registry path referenced: {run_like[0][:80]}")
            score += 8
    if "url" in strings:
        add("embedded-urls", "note",
            f"{strings['url']['count']} URL(s) embedded in the file")
        score += 3
    if "base64" in strings:
        add("base64", "note", "large base64-looking blobs present")

    pack = report.get("packing", {})
    packed = pack.get("score", 0) >= 60
    if packed:
        add("packed", "warn",
            "image is packed, so the import table and strings above are only a fragment "
            "of what the program can do")
        score += 35

    exports = report.get("pe", {}).get("exports", {}).get("count", 0)
    if report.get("pe", {}).get("kind") == "DLL" and exports >= 25:
        add("library-image", "note",
            f"DLL exporting {exports} functions: most of the capabilities above are "
            f"services it offers to whoever loads it, not necessarily its own behaviour")
        # No numeric discount here. Any factor (the old one was 0.55) is a magic
        # number that compares unrelated images: dbghelp (268 exports) came out
        # *below* dbgcore (2 exports) purely because of where the cliff sat, and the
        # export count says nothing about whether the imports are used or offered.
        # The caveat belongs in the report, not in the arithmetic.

    # -- positive evidence: take it off the score, do not just mention it ---- #
    sig = report.get("signature") or {}
    if sig.get("verified"):
        add("signature-verified", "note",
            "the embedded Authenticode signature verifies against its signer certificate")
        score -= SIGNATURE_CREDIT
    component, where = _is_windows_component(report)
    if component:
        add("windows-component", "note",
            f"ships in {where} and reports Microsoft as its publisher: the imports "
            f"above are ordinary for that role")
        score -= WINDOWS_COMPONENT_CREDIT

    # A signature that exists but does not match is the opposite of positive
    # evidence: either the file was altered after it was signed, or the signature
    # was forged outright. Either way the file must never come out 'minimal'.
    broken_sig = str(sig.get("status") or "") in (
        "MISMATCH", "digest-mismatch", "signature-invalid", "invalid")
    if broken_sig:
        add("signature-broken", "high",
            "the embedded signature does not match this file: it was either "
            "altered after signing or the signature itself was forged")
        score += 20

    score = max(0, min(score, 100))
    if score >= 65:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score >= 15:
        level = "low"
    else:
        level = "minimal"
    if broken_sig and level in ("low", "minimal"):
        level = "medium"

    signals.sort(key=lambda s: {"high": 0, "warn": 1, "note": 2}.get(s["level"], 3))
    return {"score": score, "level": level, "signals": signals}


def _verdict(report: dict[str, Any], pe: PE) -> dict[str, str]:
    peinfo = report["pe"]
    cats = report["imports"]["categories"]
    sig = report["signature"]

    if peinfo["subsystem"] in ("native", "windows-boot-driver"):
        kind = "kernel driver"
    elif peinfo["subsystem"] in ("efi-application", "efi-boot-driver", "efi-runtime-driver"):
        kind = "EFI application"
    elif "service" in cats and any(a["api"].startswith("StartServiceCtrlDispatcher")
                                   for a in cats["service"]["apis"]):
        kind = "Windows service"
    elif peinfo["kind"] == "DLL":
        kind = "DLL"
    elif peinfo["subsystem"] == "windows-gui":
        kind = "GUI application"
    elif peinfo["subsystem"] == "windows-console":
        kind = "console application"
    else:
        kind = "native image"

    dotnet = peinfo.get("dotnet")
    platform = f"{peinfo['bits']}-bit"
    head = f"{platform} {'.NET ' if dotnet else ''}{kind}"

    behaviours: list[str] = []
    if "ui" in cats:
        behaviours.append("drives a window message loop")
    if "network" in cats or "http" in cats:
        behaviours.append("talks to the network")
    if "file" in cats:
        behaviours.append("reads and writes files")
    if "registry" in cats:
        behaviours.append("touches the registry")
    if "process" in cats:
        behaviours.append("can start or open other processes")
    if "injection" in cats:
        behaviours.append("can write into another process")
    if "memory-read" in cats:
        behaviours.append("can read another process's memory")
    if "keyboard" in cats or "hook" in cats:
        behaviours.append("hooks input")
    if "download" in cats:
        behaviours.append("pulls files down from URLs")
    if not behaviours:
        behaviours.append("imports no network, file, process or UI APIs worth naming")

    notable = [s["text"] for s in report["risk"]["signals"]
               if s["level"] in ("high", "warn")][:3]

    status = sig.get("status", "")
    verified = bool(sig.get("verified"))
    signers = sig.get("signers") or []
    signer = (signers[0].get("subject") or "").split(",")[0] if signers else ""

    # Only a signature that actually verified may be described in trust language.
    # "signed", "unmodified" and "authentic" are claims about cryptography, not
    # about a number we happened to find in the file.
    if status == "valid" and verified:
        trust = (f", signed and unmodified ({signer})" if signer
                 else ", signed and unmodified")
    elif status == "valid":
        trust = ", embedded digest matches; signer identity NOT verified"
    elif status == "self-consistent":
        trust = ", embedded digest matches the signed attributes; signer identity NOT verified"
    elif status == "digest-mismatch":
        trust = ", but the embedded signature no longer matches the file"
    elif status == "signature-invalid":
        trust = ", but the embedded signature does not verify against its own certificate"
    elif status == "unsupported-algorithm":
        trust = ", with a signature whose algorithm this build does not verify"
    else:
        trust = ""

    summary = (
        f"Most likely a {head}{trust}. "
        f"From the import table: {', '.join(behaviours)}. "
    )
    if notable:
        summary += "Worth a look: " + "; ".join(notable) + ". "
    summary += f"Risk: {report['risk']['level']} ({report['risk']['score']}/100)."
    if report["packing"]["score"] >= 30:
        summary += f" Packing: {report['packing']['verdict']}."

    return {"kind": head, "summary": summary}
