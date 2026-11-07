"""Rendering: plain English for humans, stable JSON for machines."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from typing import Any, Iterable


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def magenta(self, t: str) -> str:
        return self._wrap("35", t)


def color_enabled(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM"))
    return True


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KiB", "MiB", "GiB"):
        n /= 1024.0
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if n < 100 else f"{n:.0f} {unit}"
    return f"{n} B"


def _clip(items: list[str], limit: int) -> str:
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"


LEVEL_STYLE = {"high": "red", "warn": "yellow", "note": "dim"}


def render_human(report: dict[str, Any], *, color: bool = True, width: int = 100) -> str:
    s = Style(color)
    out: list[str] = []
    w = lambda: out.append("")

    tool = report["tool"]
    out.append(s.bold(f"{tool['name']} {tool['version']}") +
               s.dim("  ·  static PE inspection  ·  the target is never executed"))
    w()

    f = report["file"]
    out.append(s.cyan(s.bold("FILE")))
    out.append(f"  path      {f['path']}")
    out.append(f"  size      {human_size(f['size'])} ({f['size']:,} bytes)")
    out.append(f"  modified  {f['mtime']}")
    out.append(f"  sha256    {f['sha256']}")
    out.append(f"  md5       {f['md5']}")
    w()

    pe = report["pe"]
    out.append(s.cyan(s.bold("HEADERS")))
    out.append(f"  format    {pe['format']}  {pe['machine']}  {pe['kind']}  "
               f"subsystem={pe['subsystem']}  linker {pe['linker']}")
    when = pe["timestamp_iso"] or "unknown"
    extra = f"  ({pe['timestamp_note']})" if pe.get("timestamp_note") else ""
    out.append(f"  compiled  {when}{extra}")
    out.append(f"  entry     {pe['entry_point']}   image base {pe['image_base']}   "
               f"image size {human_size(pe['image_size'])}")
    out.append(f"  flags     {', '.join(pe['dll_characteristics']) or '(none)'}")
    ck = pe["checksum"]
    out.append("  checksum  " + (s.green("valid") if ck["valid"]
                                 else s.yellow(f"mismatch (stored {ck['stored']})"
                                               if ck["stored"] else "not set")))
    dn = pe.get("dotnet")
    if dn:
        parts: list[str] = []
        for part in (dn.get("runtime", ""), dn.get("metadata_version", "")):
            if part and part not in parts:
                parts.append(part)
        out.append("  .NET      " + s.magenta("yes") + "  " + s.dim(" ".join(parts)) +
                   (f"  flags: {', '.join(dn.get('flags', []))}" if dn.get("flags") else ""))
    else:
        out.append("  .NET      no (native image)")
    if pe["debug"].get("pdb"):
        out.append(f"  PDB       {pe['debug']['pdb']}")
    if pe.get("rich", {}).get("present"):
        builds = ", ".join(str(b) for b, _ in pe["rich"].get("builds", [])[:5])
        out.append("  toolchain " + s.dim(f"MSVC Rich header, build(s) {builds}"))
    if pe.get("warnings"):
        for warn in pe["warnings"]:
            out.append("  " + s.yellow("warning: ") + warn)
    w()

    sig = report["signature"]
    out.append(s.cyan(s.bold("SIGNATURE")))
    status = sig.get("status", "unknown")
    label = {
        "valid": s.green("valid"),
        "digest-mismatch": s.red("MISMATCH"),
        "unsigned": s.dim("unsigned"),
        "indirect": s.yellow("catalog/indirect"),
        "unparsed": s.yellow("unparsed"),
    }.get(status, s.yellow(status))
    out.append(f"  status    {label}  {s.dim(sig.get('detail', ''))}")
    for signer in sig.get("signers", [])[:3]:
        tag = " (nested)" if signer.get("nested") else ""
        out.append(f"  signer    {signer.get('subject') or '?'}{tag}")
        out.append(f"            issuer {signer.get('issuer') or '?'}")
        if signer.get("not_before"):
            out.append(f"            cert   {signer['not_before']} -> {signer['not_after']}")
    if sig.get("timestamped"):
        out.append("  " + s.dim("timestamped by an RFC3161/countersignature authority"))
    if sig.get("present") and not sig.get("chain_verified", True):
        out.append("  " + s.dim("chain/trust not verified here (needs the Windows trust store)"))
    w()

    out.append(s.cyan(s.bold("SECTIONS")))
    out.append("  " + s.dim(f"{'name':<10}{'virt':>10}{'raw':>10}{'entropy':>9}  flags"))
    for sec in pe["sections"][:24]:
        flags = " ".join(sec["flags"])
        ent = sec["entropy"]
        ent_s = s.red(f"{ent:>8.2f}") if ent > 7.2 else f"{ent:>8.2f}"
        out.append(f"  {sec['name']:<10}{sec['virtual_size']:>10,}{sec['raw_size']:>10,}"
                   f"  {ent_s}  {flags}")
    if len(pe["sections"]) > 24:
        out.append(s.dim(f"  ... {len(pe['sections']) - 24} more sections"))
    if pe["overlay"]["size"]:
        out.append("  " + s.dim(f"overlay: {human_size(pe['overlay']['size'])} of data "
                                f"after the last section"))
    vers = pe["resources"].get("version", {})
    if vers.get("strings"):
        interesting = {k: v for k, v in vers["strings"].items()
                       if k in ("CompanyName", "ProductName", "FileDescription",
                                "FileVersion", "OriginalFilename")}
        if interesting:
            w()
            out.append(s.cyan(s.bold("VERSION INFO")))
            for k, v in interesting.items():
                out.append(f"  {k:<18} {v}")
    manifest = pe["resources"].get("manifest", {})
    if manifest.get("execution_level"):
        out.append("  " + s.dim(f"manifest requests: {manifest['execution_level']}"))
    w()

    imp = report["imports"]
    dlls_word = "DLL" if imp["dll_count"] == 1 else "DLLs"
    out.append(s.cyan(s.bold("IMPORTS")) +
               s.dim(f"  {imp['dll_count']} {dlls_word}, {imp['function_count']:,} functions, "
                     f"{imp.get('runtime_glue', 0):,} resolved to generic runtime glue, "
                     f"{imp['unclassified']:,} outside the table"))
    cats = imp["categories"]
    if not cats:
        out.append("  " + s.dim("nothing matched the capability table"))
    notable = [(name, info) for name, info in cats.items() if info["weight"] > 0]
    for name, info in notable[:9]:
        apis = []
        for a in info["apis"]:
            api = a["api"]
            apis.append(f"{a['dll'].lower()}:{api} (ordinal)" if api.startswith("#")
                        else f"{a['dll'].lower()}:{api}")
        head = f"  {name:<13}"
        out.append(head + s.dim(f"{info['count']:>3}x  ") + _clip(apis, 6))
    if len(notable) > 9:
        out.append(s.dim(f"  ... {len(notable) - 9} more categories"))
    w()

    st = report["strings"]
    out.append(s.cyan(s.bold("STRINGS")) +
               s.dim(f"  {st['total']:,} extracted, {st['unique']:,} unique" +
                     (" (truncated)" if st.get("truncated") else "")))
    shown = 0
    for name, info in st["by_category"].items():
        if shown >= 7:
            break
        shown += 1
        out.append(f"  {info['title']} " + s.dim(f"({info['count']})"))
        for sample in info["samples"][:3]:
            text = sample["text"]
            if len(text) > width - 8:
                text = text[: width - 11] + "..."
            out.append("    " + text)
    if not st["by_category"]:
        out.append("  " + s.dim("no interesting literals found"))
    w()

    pk = report["packing"]
    verdict_color = s.red if pk["score"] >= 60 else (s.yellow if pk["score"] >= 30 else s.green)
    out.append(s.cyan(s.bold("PACKING")) + "  " +
               verdict_color(f"{pk['verdict']} (score {pk['score']}/100)"))
    for reason in pk["reasons"]:
        out.append("  - " + reason)
    if not pk["reasons"]:
        out.append("  " + s.dim("- no packer signatures, normal entropy, healthy import table"))
    w()

    risk = report["risk"]
    out.append(s.cyan(s.bold("VERDICT")))
    out.append("  " + report["verdict"]["summary"])
    rcolor = {"high": s.red, "medium": s.yellow}.get(risk["level"], s.green)
    out.append("  " + rcolor(f"risk {risk['level']} ({risk['score']}/100)"))
    for sig_item in risk["signals"]:
        style = getattr(s, LEVEL_STYLE.get(sig_item["level"], "dim"))
        out.append(f"  - {style(sig_item['level'].upper()):<14} {sig_item['text']}")
    return "\n".join(out)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)


def render_compact(report: dict[str, Any]) -> str:
    """One line per file: handy for `for f in *.exe` pipelines."""
    f, risk = report["file"], report["risk"]
    return (f"{f['name']:<32} {report['verdict']['kind']:<42} "
            f"risk={risk['level']:<8} {risk['score']:>3}/100  "
            f"packing={report['packing']['score']:>3}  "
            f"{risk['signals'][0]['text'] if risk['signals'] else 'no notable capabilities'}")


# --------------------------------------------------------------------------- #
# batch tables
# --------------------------------------------------------------------------- #

#: Colour per risk level in the batch table.
BATCH_LEVEL_COLOR = {"high": "red", "medium": "yellow", "low": "cyan",
                     "minimal": "green", "error": "red"}


def batch_row(report: dict[str, Any]) -> dict[str, Any]:
    """Flatten one full report into the four columns the batch table shows.

    The one-liner leads with the verdict kind, then the most serious signal:
    a batch row is a pointer to the file worth opening, not a summary of the
    whole report. Nothing is recomputed here; every field is copied.
    """
    risk = report["risk"]
    signals = risk.get("signals") or []
    top = next((s for s in signals if s["level"] in ("high", "warn")), None)
    if top is None:
        top = signals[0] if signals else None
    kind = report["verdict"]["kind"]
    summary = f"{kind}: {top['text']}" if top else f"{kind}: nothing notable in the import table"
    return {
        "path": report["file"]["path"],
        "name": report["file"]["name"],
        "score": risk["score"],
        "level": risk["level"],
        "verdict": summary,
    }


def _batch_cell(text: str, width: int) -> str:
    """Collapse whitespace and clip to ``width`` so a row always stays one line."""
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3].rstrip() + "..."


def render_batch_table(rows: Iterable[dict[str, Any]], *, color: bool = False,
                       width: int = 120) -> str:
    """Risk-sorted table: score, level, file name, one-line verdict.

    Rows arrive in the order they are printed (the caller sorts). An error row
    carries ``score=None`` and an ``error`` message instead of a verdict.
    """
    s = Style(color)
    rows = list(rows)
    if not rows:
        return s.dim("no file matched --batch and --min-risk-level")

    name_w = min(max([len(row["name"]) for row in rows] + [len("FILE")]), 40)
    fixed = 5 + 2 + 7 + 2 + name_w + 2
    verdict_w = max(width - fixed, 24)

    head = f"{'SCORE':>5}  {'LEVEL':<7}  {'FILE':<{name_w}}  VERDICT"
    out = [s.bold(head), s.dim("-" * (fixed + verdict_w))]

    for row in rows:
        level = row.get("level", "error")
        score = row.get("score")
        score_s = f"{score:>5}" if isinstance(score, int) else f"{'--':>5}"
        level_s = f"{level:<7}"
        paint = getattr(s, BATCH_LEVEL_COLOR.get(level, "dim"), s.dim)
        verdict = row.get("verdict") or row.get("error") or ""
        out.append(
            f"{score_s}  {paint(level_s)}  {row['name']:<{name_w}}  "
            f"{_batch_cell(verdict, verdict_w)}"
        )
    return "\n".join(out)


def render_batch_csv(rows: Iterable[dict[str, Any]],
                     *, errors: Iterable[dict[str, str]] = ()) -> str:
    """Same rows as CSV for pipelines; errors keep the schema with an empty score."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["score", "level", "name", "path", "verdict"])
    for row in rows:
        writer.writerow([row.get("score", ""), row.get("level", ""), row.get("name", ""),
                         row.get("path", ""), row.get("verdict", "")])
    for err in errors:
        writer.writerow(["", "error", os.path.basename(err.get("path", "")),
                         err.get("path", ""), err.get("error", "")])
    return buf.getvalue().rstrip("\n")


def render_batch_footer(stats: dict[str, Any], *, color: bool = False) -> str:
    """One line under the table: what was scanned, listed, filtered and broken."""
    s = Style(color)
    parts = [f"scanned {stats.get('analysed', 0)} of {stats.get('candidates', 0)} candidate(s)",
             f"listed {stats.get('shown', 0)}"]
    if stats.get("filtered"):
        parts.append(f"filtered {stats['filtered']} below {stats.get('min_risk_level', 'minimal')}")
    errors = stats.get("errors", 0)
    parts.append(s.red(f"errors {errors}") if errors else s.dim("errors 0"))
    if stats.get("unreadable_dirs"):
        parts.append(s.dim(f"{stats['unreadable_dirs']} unreadable dir(s)"))
    if stats.get("truncated"):
        parts.append(f"--max-files stopped at {stats.get('selected', 0)}")
    if stats.get("interrupted"):
        parts.append(s.red("INTERRUPTED"))
    return "  ·  ".join(parts)
