"""Command line entry point: ``python -m exe_xray`` or ``xray.py``."""

from __future__ import annotations

import argparse
import re
import sys

from . import VERSION
from .analyze import AnalysisError, analyze
from .pe import checksum_verification
from .report import color_enabled, render_compact, render_human, render_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exe-xray",
        description=(
            "Static health report for Windows executables (EXE/DLL). "
            "Nothing is executed, loaded or emulated: only the file bytes are read."
        ),
        epilog="examples:\n"
               "  xray.py C:\\Windows\\System32\\notepad.exe\n"
               "  xray.py build\\app.exe --json > app.json\n"
               "  xray.py *.exe --compact\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="+", help="PE file(s) to inspect")
    p.add_argument("--json", action="store_true",
                   help="emit the full structured report instead of prose")
    p.add_argument("--compact", action="store_true",
                   help="one summary line per file (ignored with --json)")
    p.add_argument("--min-string-len", type=int, default=4, metavar="N",
                   help="shortest literal to keep (default: 4)")
    p.add_argument("--max-strings", type=int, default=4000, metavar="N",
                   help="cap on samples kept per string category (default: 4000)")
    p.add_argument("--no-strings", action="store_true",
                   help="skip literal extraction (worth it on string-dense files; "
                        "the checksum pass is usually the bigger cost)")
    p.add_argument("--no-checksum", action="store_true",
                   help="skip the PE checksum verification, the most expensive pass "
                        "over the file (a 200 MB+ image goes from minutes to "
                        "seconds); the report then says the checksum was not verified")
    p.add_argument("--max-file-mb", type=int, default=512, metavar="MB",
                   help="refuse files larger than this (default: 512)")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="ANSI colour policy (default: auto)")
    p.add_argument("--version", action="version", version=f"exe-xray {VERSION}")
    return p


CHECKSUM_LINE = re.compile(r"^[ \t]*checksum  .*$", re.MULTILINE)


def _mark_checksum_skipped(report: dict) -> None:
    """Replace the validity verdict with an explicit "not verified" marker.

    With --no-checksum the checksum pass never runs, so neither the computed
    value nor the comparison exists. Saying so beats printing a stale "valid"
    (or a false "mismatch"): both fields carry null and ``skipped`` is set.
    """
    pe = report.get("pe")
    if isinstance(pe, dict):
        stored = (pe.get("checksum") or {}).get("stored", "")
        pe["checksum"] = {
            "stored": stored,
            "computed": None,
            "valid": None,
            "skipped": True,
        }


def _rewrite_checksum_line(text: str) -> str:
    """Same marker in the prose renderer, without teaching report.py the flag."""
    return CHECKSUM_LINE.sub("  checksum  not verified (--no-checksum)", text, count=1)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    args = build_parser().parse_args(argv)

    if args.min_string_len < 1:
        print("error: --min-string-len must be >= 1", file=sys.stderr)
        return 2
    if args.max_file_mb < 1:
        print("error: --max-file-mb must be >= 1", file=sys.stderr)
        return 2

    multi = len(args.path) > 1
    reports: list[dict] = []
    failures = 0

    with checksum_verification(not args.no_checksum):
        for path in args.path:
            try:
                report = analyze(
                    path,
                    max_strings=args.max_strings,
                    min_string_len=args.min_string_len,
                    max_file_mb=args.max_file_mb,
                    skip_strings=args.no_strings,
                )
            except AnalysisError as exc:
                failures += 1
                print(f"{path}: error: {exc}", file=sys.stderr)
                continue
            if args.no_checksum:
                _mark_checksum_skipped(report)
            reports.append(report)

    if args.json:
        if multi or not reports:
            payload = reports
        else:
            payload = reports[0]
        print(render_json(payload))
        return 0 if reports else 1

    color = color_enabled(args.color)
    for i, report in enumerate(reports):
        if args.compact or multi:
            print(render_compact(report))
        else:
            text = render_human(report, color=color)
            if args.no_checksum:
                text = _rewrite_checksum_line(text)
            print(text)

    if failures and not reports:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
