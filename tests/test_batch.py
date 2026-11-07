"""Tests for ``--batch``: discovery, table, CSV, exit codes, resilience.

Run with ``python -m unittest discover -s tests -v``. Every case builds its own
throw-away tree under ``tempfile`` and copies in the in-memory specimens from
``make_fixtures``; nothing here touches the shared ``tests/fixtures`` directory,
nothing is executed and nothing touches the network.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (ROOT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import make_fixtures  # noqa: E402

from exe_xray import cli  # noqa: E402
from exe_xray.analyze import analyze  # noqa: E402
from exe_xray.report import batch_row, render_batch_csv, render_batch_table  # noqa: E402

SPECIMENS: dict[str, str] = {}
_SPECIMEN_DIR = ""


def setUpModule() -> None:
    global _SPECIMEN_DIR
    _SPECIMEN_DIR = tempfile.mkdtemp(prefix="exe-xray-specimens-")
    for name, factory in (("clean.exe", make_fixtures.clean_exe),
                          ("packed.exe", make_fixtures.packed_exe),
                          ("suspicious.exe", make_fixtures.suspicious_exe)):
        with open(os.path.join(_SPECIMEN_DIR, name), "wb") as fh:
            fh.write(factory())
        SPECIMENS[name] = os.path.join(_SPECIMEN_DIR, name)


def tearDownModule() -> None:
    shutil.rmtree(_SPECIMEN_DIR, ignore_errors=True)


def table_rows(text: str) -> list[dict[str, str]]:
    """Parse the rendered table back into rows (header and rule are dropped)."""
    rows: list[dict[str, str]] = []
    for line in text.splitlines()[2:]:
        if not line.strip() or line.startswith("scanned "):
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 3:
            continue
        rows.append({
            "score": parts[0],
            "level": parts[1],
            "name": parts[2],
            "verdict": parts[3] if len(parts) > 3 else "",
        })
    return rows


class BatchCase(unittest.TestCase):
    """Shared scaffolding: a private tree per test plus a captured ``main()``."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="exe-xray-batch-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, relpath: str, specimen: str | bytes) -> str:
        dest = os.path.join(self.tmp, relpath)
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if isinstance(specimen, bytes):
            with open(dest, "wb") as fh:
                fh.write(specimen)
        else:
            shutil.copyfile(SPECIMENS[specimen], dest)
        return dest

    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = cli.main(argv)
        finally:
            sys.stdout, sys.stderr = stdout, stderr
        return code, out.getvalue(), err.getvalue()


class TestBatchTable(BatchCase):
    def test_lists_every_specimen_sorted_by_score(self) -> None:
        self.put("clean.exe", "clean.exe")
        self.put("packed.exe", "packed.exe")
        self.put("suspicious.exe", "suspicious.exe")

        code, out, err = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("SCORE", out)
        self.assertIn("LEVEL", out)
        self.assertIn("VERDICT", out)
        rows = table_rows(out)
        self.assertEqual([r["name"] for r in rows],
                         ["suspicious.exe", "packed.exe", "clean.exe"])
        self.assertEqual([r["score"] for r in rows], ["100", "35", "0"])
        self.assertEqual([r["level"] for r in rows], ["high", "medium", "minimal"])
        # every row must carry a one-line judgement, not an empty column
        for row in rows:
            self.assertTrue(row["verdict"].strip(), row)

    def test_recursion_and_extension_filter(self) -> None:
        self.put("top.exe", "clean.exe")
        self.put(os.path.join("nested", "deep", "inner.dll"), "packed.exe")
        self.put(os.path.join("nested", "driver.sys"), "clean.exe")
        self.put(os.path.join("nested", "notes.txt"), b"not a PE, ignore me\n")
        self.put(os.path.join("nested", "script.py"), b"print('ignore me')\n")
        self.put(os.path.join("nested", "lower.EXE"), "clean.exe")

        code, out, err = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK, err)
        names = {r["name"] for r in table_rows(out)}
        self.assertEqual(names, {"top.exe", "inner.dll", "driver.sys", "lower.EXE"})

    def test_glob_target_only_matches_exe(self) -> None:
        self.put("a.exe", "clean.exe")
        self.put("b.dll", "clean.exe")
        pattern = os.path.join(self.tmp, "*.exe")

        code, out, _err = self.run_cli(["--batch", pattern, "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual([r["name"] for r in table_rows(out)], ["a.exe"])

    def test_glob_matching_nothing_is_reported(self) -> None:
        code, out, err = self.run_cli(
            ["--batch", os.path.join(self.tmp, "nothing-*.dll"), "--color", "never"])

        self.assertEqual(code, cli.EXIT_NOTHING_ANALYSED)
        self.assertIn("matched nothing", err)
        self.assertIn("no file matched", out)

    def test_max_files_caps_the_scan(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)

        code, out, _err = self.run_cli(
            ["--batch", self.tmp, "--max-files", "2", "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK)
        rows = table_rows(out)
        self.assertEqual(len(rows), 2)
        # in path order the first two candidates are clean.exe and packed.exe
        self.assertEqual({r["name"] for r in rows}, {"clean.exe", "packed.exe"})
        self.assertIn("--max-files stopped at 2", out)

    def test_min_risk_level_filters(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)

        code, out, _err = self.run_cli(
            ["--batch", self.tmp, "--min-risk-level", "high", "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual([r["name"] for r in table_rows(out)], ["suspicious.exe"])
        self.assertIn("filtered 2 below high", out)

    def test_min_risk_level_medium_keeps_medium_and_high(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)

        _code, out, _err = self.run_cli(
            ["--batch", self.tmp, "--min-risk-level", "medium", "--color", "never"])

        self.assertEqual([r["name"] for r in table_rows(out)],
                         ["suspicious.exe", "packed.exe"])

    def test_output_is_deterministic(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)

        first = self.run_cli(["--batch", self.tmp, "--color", "never"])
        second = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(first, second)

    def test_table_lines_never_wrap(self) -> None:
        rows = [{"path": r"c:\x\a.exe", "name": "a.exe", "score": 100, "level": "high",
                 "verdict": "32-bit GUI application: " + "injects into another process " * 12}]

        table = render_batch_table(rows, width=120)

        for line in table.splitlines():
            self.assertLessEqual(len(line), 120, line)


class TestBatchCsv(BatchCase):
    def test_csv_header_rows_and_order(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)

        code, out, err = self.run_cli(["--batch", self.tmp, "--csv"])

        self.assertEqual(code, cli.EXIT_OK, err)
        reader = csv.DictReader(io.StringIO(out))
        self.assertEqual(reader.fieldnames, ["score", "level", "name", "path", "verdict"])
        rows = list(reader)
        self.assertEqual([r["name"] for r in rows],
                         ["suspicious.exe", "packed.exe", "clean.exe"])
        self.assertEqual([r["score"] for r in rows], ["100", "35", "0"])
        self.assertTrue(all(r["path"].startswith(self.tmp) for r in rows))

    def test_csv_quotes_awkward_paths(self) -> None:
        self.put(os.path.join("a, b", "clean.exe"), "clean.exe")

        code, out, _err = self.run_cli(["--batch", self.tmp, "--csv"])

        self.assertEqual(code, cli.EXIT_OK)
        rows = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["path"].endswith("clean.exe"))

    def test_csv_has_no_ansi_sequences(self) -> None:
        self.put("suspicious.exe", "suspicious.exe")

        _code, out, _err = self.run_cli(["--batch", self.tmp, "--csv", "--color", "always"])

        self.assertNotIn("\x1b[", out)

    def test_csv_carries_error_rows(self) -> None:
        self.put("clean.exe", "clean.exe")
        self.put("broken.exe", b"definitely not a PE image\n")

        code, out, err = self.run_cli(["--batch", self.tmp, "--csv"])

        self.assertEqual(code, cli.EXIT_OK, err)
        rows = list(csv.DictReader(io.StringIO(out)))
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["broken.exe"]["level"], "error")
        self.assertEqual(by_name["broken.exe"]["score"], "")
        self.assertIn("not a Windows executable", by_name["broken.exe"]["verdict"])

    def test_render_batch_csv_is_pure(self) -> None:
        rows = [{"path": r"c:\x\a.exe", "name": "a.exe", "score": 7, "level": "low",
                 "verdict": "ok"}]
        errors = [{"path": r"c:\x\b.dll", "error": "boom", "kind": "file"}]

        text = render_batch_csv(rows, errors=errors)

        self.assertEqual(text.splitlines()[0], "score,level,name,path,verdict")
        self.assertEqual(len(text.splitlines()), 3)


class TestBatchResilience(BatchCase):
    def test_one_broken_file_does_not_end_the_run(self) -> None:
        self.put("broken.exe", b"MZ but truncated garbage")
        self.put("clean.exe", "clean.exe")
        self.put("suspicious.exe", "suspicious.exe")

        code, out, err = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK, err)
        names = [r["name"] for r in table_rows(out)]
        self.assertEqual(names, ["suspicious.exe", "clean.exe"])
        self.assertIn("broken.exe: error:", err)
        self.assertIn("errors 1", out)

    def test_empty_directory_is_not_a_success(self) -> None:
        self.put("notes.txt", b"nothing here\n")

        code, out, _err = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(code, cli.EXIT_NOTHING_ANALYSED)
        self.assertIn("no file matched", out)
        self.assertIn("errors 0", out)

    def test_missing_batch_target_is_reported(self) -> None:
        code, _out, err = self.run_cli(
            ["--batch", os.path.join(self.tmp, "absent"), "--color", "never"])

        self.assertEqual(code, cli.EXIT_NOTHING_ANALYSED)
        self.assertIn("no such file or directory", err)

    def test_ctrl_c_prints_partial_results(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)
        real = cli.analyze
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] > 1:
                raise KeyboardInterrupt
            return real(*args, **kwargs)

        with mock.patch.object(cli, "analyze", side_effect=flaky):
            code, out, err = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(code, cli.EXIT_INTERRUPTED, err)
        self.assertIn("INTERRUPTED", out)
        self.assertEqual([r["name"] for r in table_rows(out)], ["clean.exe"])
        self.assertIn("interrupted", err)

    def test_each_file_is_analyzed_exactly_once(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            self.put(name, name)
        real = cli.analyze
        seen: list[str] = []

        def counting(path, *args, **kwargs):
            seen.append(os.path.basename(path))
            return real(path, *args, **kwargs)

        with mock.patch.object(cli, "analyze", side_effect=counting):
            code, _out, err = self.run_cli(["--batch", self.tmp, "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertEqual(sorted(seen), ["clean.exe", "packed.exe", "suspicious.exe"])


class TestBatchJson(BatchCase):
    def test_json_carries_counts_rows_and_errors(self) -> None:
        self.put("clean.exe", "clean.exe")
        self.put("broken.dll", b"nope\n")

        code, out, err = self.run_cli(["--batch", self.tmp, "--json"])

        self.assertEqual(code, cli.EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["batch"]["candidates"], 2)
        self.assertEqual(payload["batch"]["analysed"], 1)
        self.assertEqual(payload["batch"]["errors"], 1)
        self.assertEqual([row["name"] for row in payload["rows"]], ["clean.exe"])
        self.assertEqual(payload["errors"][0]["kind"], "file")


class TestFailOnRisk(BatchCase):
    def test_gate_passes_below_threshold(self) -> None:
        self.put("clean.exe", "clean.exe")

        code, out, err = self.run_cli(
            ["--batch", self.tmp, "--fail-on-risk", "1", "--color", "never"])

        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertNotIn("risk gate", err)
        self.assertIn("clean.exe", out)

    def test_gate_trips_at_threshold(self) -> None:
        self.put("clean.exe", "clean.exe")
        self.put("suspicious.exe", "suspicious.exe")

        code, _out, err = self.run_cli(
            ["--batch", self.tmp, "--fail-on-risk", "65", "--color", "never"])

        self.assertEqual(code, cli.EXIT_NOTHING_ANALYSED)
        self.assertIn("risk gate: 1 file(s) at or above 65/100", err)

    def test_gate_is_inclusive_of_the_threshold(self) -> None:
        self.put("packed.exe", "packed.exe")  # scores 35

        tight, _out, _err = self.run_cli(
            ["--batch", self.tmp, "--fail-on-risk", "35", "--color", "never"])
        loose, _out2, _err2 = self.run_cli(
            ["--batch", self.tmp, "--fail-on-risk", "36", "--color", "never"])

        self.assertEqual(tight, cli.EXIT_NOTHING_ANALYSED)
        self.assertEqual(loose, cli.EXIT_OK)

    def test_gate_applies_to_single_file_mode(self) -> None:
        code, _out, err = self.run_cli(
            [SPECIMENS["suspicious.exe"], "--fail-on-risk", "90", "--color", "never"])

        self.assertEqual(code, cli.EXIT_NOTHING_ANALYSED)
        self.assertIn("risk gate", err)

    def test_gate_only_sees_listed_rows(self) -> None:
        """``--min-risk-level`` decides what the gate looks at, on purpose.

        A clean image hidden by the filter cannot trip a gate of 0: the table
        and the gate describe the same set of rows, so a CI log never says
        "gate tripped" while showing nothing that tripped it.
        """
        self.put("clean.exe", "clean.exe")  # scores 0, level minimal

        listed, out, err = self.run_cli(
            ["--batch", self.tmp, "--min-risk-level", "low",
             "--fail-on-risk", "0", "--color", "never"])
        unfiltered, _out2, err2 = self.run_cli(
            ["--batch", self.tmp, "--fail-on-risk", "0", "--color", "never"])

        self.assertEqual(listed, cli.EXIT_OK, err)
        self.assertIn("no file matched", out)
        self.assertNotIn("risk gate", err)
        self.assertEqual(unfiltered, cli.EXIT_NOTHING_ANALYSED)
        self.assertIn("risk gate: 1 file(s) at or above 0/100", err2)


class TestBatchUsage(BatchCase):
    def test_batch_rejects_extra_paths(self) -> None:
        code, _out, err = self.run_cli(["--batch", self.tmp, SPECIMENS["clean.exe"]])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("--batch takes a directory or glob", err)

    def test_no_input_at_all(self) -> None:
        code, _out, err = self.run_cli([])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("no input", err)

    def test_csv_outside_batch(self) -> None:
        code, _out, err = self.run_cli([SPECIMENS["clean.exe"], "--csv"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("--csv only applies to --batch", err)

    def test_csv_and_json_cannot_both_win(self) -> None:
        code, _out, err = self.run_cli(["--batch", self.tmp, "--csv", "--json"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("pick one output format", err)

    def test_max_files_must_be_positive(self) -> None:
        code, _out, err = self.run_cli(["--batch", self.tmp, "--max-files", "0"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("--max-files must be >= 1", err)

    def test_fail_on_risk_range(self) -> None:
        for value in ("-1", "101"):
            code, _out, err = self.run_cli(["--batch", self.tmp, "--fail-on-risk", value])
            self.assertEqual(code, cli.EXIT_USAGE, value)
            self.assertIn("between 0 and 100", err)

    def test_unknown_min_risk_level(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.run_cli(["--batch", self.tmp, "--min-risk-level", "critical"])
        self.assertEqual(caught.exception.code, cli.EXIT_USAGE)


class TestBatchRow(BatchCase):
    def test_row_is_a_faithful_projection(self) -> None:
        report = analyze(SPECIMENS["suspicious.exe"])
        row = batch_row(report)

        self.assertEqual(row["score"], report["risk"]["score"])
        self.assertEqual(row["level"], report["risk"]["level"])
        self.assertEqual(row["name"], "suspicious.exe")
        self.assertEqual(row["path"], report["file"]["path"])
        self.assertTrue(row["verdict"].startswith(report["verdict"]["kind"] + ": "))
        self.assertNotIn("\n", row["verdict"])
        self.assertGreaterEqual(row["score"], 65)

    def test_clean_row_still_has_a_judgement(self) -> None:
        row = batch_row(analyze(SPECIMENS["clean.exe"]))
        self.assertEqual(row["score"], 0)
        self.assertEqual(row["level"], "minimal")
        self.assertTrue(row["verdict"].strip())


if __name__ == "__main__":
    unittest.main()
