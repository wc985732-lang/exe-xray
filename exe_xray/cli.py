"""Command line entry point: ``python -m exe_xray`` or ``xray.py``."""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from typing import Any, Iterator

from . import VERSION
from .analyze import AnalysisError, analyze
from .pe import checksum_verification
from .report import (
    batch_row,
    color_enabled,
    render_batch_csv,
    render_batch_footer,
    render_batch_table,
    render_compact,
    render_human,
    render_json,
)

# Exit codes. They are part of the interface: a CI job branches on them.
EXIT_OK = 0
EXIT_NOTHING_ANALYSED = 1   # no report was produced, or the --fail-on-risk gate tripped
EXIT_USAGE = 2              # bad arguments
EXIT_INTERRUPTED = 130      # Ctrl+C; whatever was scanned is still printed

#: File extensions a batch scan treats as PE images (case-insensitive).
BATCH_SUFFIXES = (".exe", ".dll", ".sys", ".cpl", ".scr", ".ocx")

#: Ordering used by ``--min-risk-level``.
RISK_ORDER = {"minimal": 0, "low": 1, "medium": 2, "high": 3}

_GLOB_CHARS = ("*", "?", "[")


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
               "  xray.py *.exe --compact\n"
               "  xray.py --batch C:\\Windows\\System32 --max-files 50\n"
               "  xray.py --batch . --csv > triage.csv\n"
               "  xray.py --batch dist --fail-on-risk 70   (CI gate: exit 1 on a hit)\n"
               "\n"
               "exit codes:\n"
               "  0    every analyzed file was read successfully; --fail-on-risk (if given)\n"
               "       found nothing at or above the threshold\n"
               "  1    nothing could be analyzed, or --fail-on-risk tripped (CI gate)\n"
               "  2    bad command line\n"
               "  130  interrupted (Ctrl+C); the files scanned so far are printed first\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="*", help="PE file(s) to inspect")
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

    batch = p.add_argument_group(
        "batch mode",
        "Scan a whole directory (or a glob) and print one risk-sorted table.",
    )
    batch.add_argument("--batch", metavar="PATH", default=None,
                       help="directory, glob or single file to scan recursively for "
                            + "/".join(BATCH_SUFFIXES))
    batch.add_argument("--max-files", type=int, default=500, metavar="N",
                       help="stop after N files were analyzed, in path order "
                            "(default: 500; 0 or a negative value is a usage error)")
    batch.add_argument("--min-risk-level", choices=sorted(RISK_ORDER, key=RISK_ORDER.get),
                       default="minimal",
                       help="only list files at or above this risk level "
                            "(default: minimal, i.e. everything)")
    batch.add_argument("--csv", action="store_true",
                       help="emit CSV instead of the table (score,level,name,path,verdict)")
    batch.add_argument("--fail-on-risk", type=int, default=None, metavar="N",
                       help="exit 1 when any analyzed file scores N/100 or more; "
                            "the CI gate. Applies to batch and single-file mode")

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


# --------------------------------------------------------------------------- #
# batch discovery
# --------------------------------------------------------------------------- #

def _has_wildcard(text: str) -> bool:
    return any(ch in text for ch in _GLOB_CHARS)


def _walk(root: str, problems: list[tuple[str, str]]) -> Iterator[str]:
    """Walk ``root``, turning an unreadable directory into a problem, not a crash."""

    def onerror(exc: OSError) -> None:
        where = getattr(exc, "filename", None) or root
        problems.append((str(where), f"cannot list directory: {exc.strerror or exc}"))

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        dirnames.sort()
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def discover(target: str, *, recursive: bool = True) -> tuple[list[str], list[tuple[str, str]]]:
    """Resolve ``--batch`` into PE candidates plus the paths that could not be read.

    A directory is walked recursively and filtered by :data:`BATCH_SUFFIXES`.
    A glob is expanded (``**`` works with ``recursive=True``) and each match is
    treated like a directory or a file. A single explicit file is taken as-is,
    whatever its extension: naming one file is a deliberate act, and the
    analyzer will explain itself if the bytes are not a PE.
    """
    files: list[str] = []
    problems: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(path: str, *, force: bool = False) -> None:
        if not force and os.path.splitext(path)[1].lower() not in BATCH_SUFFIXES:
            return
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            return
        seen.add(key)
        files.append(os.path.abspath(path))

    if _has_wildcard(target):
        matches = sorted(glob.glob(target, recursive=recursive))
        if not matches:
            problems.append((target, "the glob matched nothing"))
        for match in matches:
            if os.path.isdir(match):
                for found in _walk(match, problems):
                    add(found)
            elif os.path.isfile(match):
                add(match)
    elif os.path.isdir(target):
        for found in _walk(target, problems):
            add(found)
    elif os.path.isfile(target):
        add(target, force=True)
    else:
        problems.append((target, "no such file or directory"))

    files.sort(key=lambda p: (os.path.dirname(p).lower(), os.path.basename(p).lower()))
    return files, problems


# --------------------------------------------------------------------------- #
# batch run
# --------------------------------------------------------------------------- #

def _analyze_one(path: str, args: argparse.Namespace) -> dict[str, Any]:
    """One file through the shared analyzer: no extra read, no second parse."""
    report = analyze(
        path,
        max_strings=args.max_strings,
        min_string_len=args.min_string_len,
        max_file_mb=args.max_file_mb,
        skip_strings=args.no_strings,
    )
    if args.no_checksum:
        _mark_checksum_skipped(report)
    return report


def _run_batch(args: argparse.Namespace) -> int:
    candidates, problems = discover(args.batch)
    errors: list[dict[str, str]] = []

    for where, message in problems:
        errors.append({"path": where, "error": message, "kind": "directory"})
        print(f"{where}: error: {message}", file=sys.stderr)

    selected = candidates[: max(args.max_files, 0)]
    rows: list[dict[str, Any]] = []
    interrupted = False

    with checksum_verification(not args.no_checksum):
        try:
            for path in selected:
                try:
                    rows.append(batch_row(_analyze_one(path, args)))
                except AnalysisError as exc:
                    # One broken file must never end the run.
                    errors.append({"path": path, "error": str(exc), "kind": "file"})
                    print(f"{path}: error: {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            interrupted = True
            print("interrupted: printing what has been scanned so far", file=sys.stderr)

    floor = RISK_ORDER[args.min_risk_level]
    shown = [row for row in rows if RISK_ORDER[row["level"]] >= floor]
    shown.sort(key=lambda row: (-row["score"], row["name"].lower(), row["path"].lower()))

    file_errors = sum(1 for err in errors if err["kind"] == "file")
    stats = {
        "candidates": len(candidates),
        "selected": len(selected),
        "analysed": len(rows),
        "shown": len(shown),
        "filtered": len(rows) - len(shown),
        "errors": file_errors,
        "unreadable_dirs": len(errors) - file_errors,
        "min_risk_level": args.min_risk_level,
        "truncated": len(candidates) > len(selected),
        "interrupted": interrupted,
    }

    color = color_enabled(args.color)
    if args.json:
        print(render_json({"batch": stats, "rows": shown, "errors": errors}))
    elif args.csv:
        # A row is a file. Unreadable *directories* are environment news, not
        # files, so they stay on stderr and in the footer count.
        print(render_batch_csv(shown, errors=[e for e in errors if e["kind"] == "file"]))
    else:
        print(render_batch_table(shown, color=color))
        print(render_batch_footer(stats, color=color))

    tripped = _gate(args.fail_on_risk, [row["score"] for row in shown])
    if tripped:
        print(f"risk gate: {tripped} file(s) at or above {args.fail_on_risk}/100",
              file=sys.stderr)

    if interrupted:
        return EXIT_INTERRUPTED
    if tripped:
        return EXIT_NOTHING_ANALYSED
    if not rows:
        return EXIT_NOTHING_ANALYSED
    return EXIT_OK


def _gate(threshold: int | None, scores: list[int]) -> int:
    """Count the files at or above the ``--fail-on-risk`` threshold."""
    if threshold is None:
        return 0
    return sum(1 for score in scores if score >= threshold)


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    args = build_parser().parse_args(argv)

    if args.min_string_len < 1:
        print("error: --min-string-len must be >= 1", file=sys.stderr)
        return EXIT_USAGE
    if args.max_file_mb < 1:
        print("error: --max-file-mb must be >= 1", file=sys.stderr)
        return EXIT_USAGE
    if args.batch is not None and args.path:
        print("error: --batch takes a directory or glob; drop the extra file arguments",
              file=sys.stderr)
        return EXIT_USAGE
    if args.batch is None and not args.path:
        print("error: no input: pass one or more PE files, or --batch PATH", file=sys.stderr)
        return EXIT_USAGE
    if args.max_files < 1:
        print("error: --max-files must be >= 1", file=sys.stderr)
        return EXIT_USAGE
    if args.fail_on_risk is not None and not 0 <= args.fail_on_risk <= 100:
        print("error: --fail-on-risk must be between 0 and 100", file=sys.stderr)
        return EXIT_USAGE
    if args.csv and args.batch is None:
        print("error: --csv only applies to --batch", file=sys.stderr)
        return EXIT_USAGE
    if args.csv and args.json:
        print("error: pick one output format: --csv or --json", file=sys.stderr)
        return EXIT_USAGE

    if args.batch is not None:
        return _run_batch(args)

    multi = len(args.path) > 1
    reports: list[dict] = []
    failures = 0

    with checksum_verification(not args.no_checksum):
        for path in args.path:
            try:
                reports.append(_analyze_one(path, args))
            except AnalysisError as exc:
                failures += 1
                print(f"{path}: error: {exc}", file=sys.stderr)
                continue

    if args.json:
        if multi or not reports:
            payload = reports
        else:
            payload = reports[0]
        print(render_json(payload))
        tripped = _gate(args.fail_on_risk,
                        [r["risk"]["score"] for r in reports])
        if tripped:
            print(f"risk gate: {tripped} file(s) at or above {args.fail_on_risk}/100",
                  file=sys.stderr)
        if not reports:
            return EXIT_NOTHING_ANALYSED
        return EXIT_NOTHING_ANALYSED if tripped else EXIT_OK

    color = color_enabled(args.color)
    for report in reports:
        if args.compact or multi:
            print(render_compact(report))
        else:
            text = render_human(report, color=color)
            if args.no_checksum:
                text = _rewrite_checksum_line(text)
            print(text)

    tripped = _gate(args.fail_on_risk, [r["risk"]["score"] for r in reports])
    if tripped:
        print(f"risk gate: {tripped} file(s) at or above {args.fail_on_risk}/100",
              file=sys.stderr)

    if tripped:
        return EXIT_NOTHING_ANALYSED
    if failures and not reports:
        return EXIT_NOTHING_ANALYSED
    return EXIT_OK


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(EXIT_INTERRUPTED)
