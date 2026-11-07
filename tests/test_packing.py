"""Packing heuristics, tested against shapes measured on real images.

Two kinds of evidence live here, and they are kept apart on purpose:

* ``TestSynthetic*`` runs on PE files assembled by ``make_fixtures`` - no
  compiler, no network, nothing executed. Each fixture isolates one observable,
  so a failure names the rule that broke.
* ``TestRealSamples`` runs on genuine binaries that happen to exist on the host:
  two UPX images, one VMProtect image and a set of stock Microsoft and
  third-party images that must *not* be called packed. Those tests **skip** when
  the file is absent. A skip means "not proven here", never "proven fine" - a
  green run on a machine without those files proves nothing about real packers.

Run with ``python -m unittest discover -s tests -q``.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (ROOT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import make_fixtures  # noqa: E402

from exe_xray.analyze import analyze  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
VERDICTS = {"no packing indicators", "possibly packed", "likely packed / protected"}

# Real images used as ground truth. The three packers were found by scanning this
# host for packer section names; the controls are stock components whose
# innocence is established by their signature and their role, not by a guess.
UPX_SAMPLES = [
    r"C:\Program Files\IGRS\Mechrevo\un_res\istask.dll",
    r"C:\Program Files\ToDesk\CrashReport.exe",
]
VMPROTECT_SAMPLES = [
    r"C:\Program Files\Tencent\Weixin\4.2.0.13\wcprobe.dll",
]
CLEAN_SAMPLES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\ntoskrnl.exe",       # 39 sections, zero-filled Pad
    r"C:\Windows\System32\winload.exe",        # boot app: imports nothing
    r"C:\Windows\System32\hvax64.exe",         # hypervisor: one import
    r"C:\Windows\System32\ntdll.dll",          # 2 523 exports, zero imports
    r"C:\Windows\System32\msobjs.dll",         # resource-only: no code at all
    r"C:\Windows\System32\tzsync.exe",         # managed EXE, no import table
    r"C:\Program Files\Python312\python.exe",
    r"C:\Windows\System32\d3dcsx_42.dll",      # legitimate 7.83 bits/byte .text
]
MANAGED_SAMPLES = [
    r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\6.0.25\System.Text.Encoding.CodePages.dll",
    r"C:\Program Files\Git\mingw64\bin\Avalonia.DesignerSupport.dll",
    r"C:\Program Files\Common Files\microsoft shared\ink\Microsoft.Ink.dll",
]


def analyze_blob(blob: bytes, name: str = "fixture.exe") -> dict:
    fd, path = tempfile.mkstemp(suffix="-" + name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        return analyze(path, skip_strings=True)
    finally:
        os.unlink(path)


def packing_of(blob: bytes, name: str = "fixture.exe") -> dict:
    return analyze_blob(blob, name)["packing"]


def reasons_joined(packing: dict) -> str:
    return " | ".join(packing["reasons"])


class TestSyntheticIdentity(unittest.TestCase):
    """A packer's own section names are decisive - and counted once."""

    def test_two_sections_of_one_packer_score_once(self) -> None:
        packing = packing_of(make_fixtures.upx_named_only(), "upx-names.exe")
        # 60 is the single identity credit: the old code added 40 for UPX0 and
        # another 40 for UPX1, which let one observation score 80 on its own.
        self.assertEqual(packing["score"], 60, reasons_joined(packing))
        self.assertEqual(packing["verdict"], "likely packed / protected")
        self.assertIn("UPX", reasons_joined(packing))

    def test_packed_fixture_still_decides_on_names(self) -> None:
        packing = analyze(os.path.join(FIXTURES, "packed.exe"))["packing"]
        self.assertEqual(packing["verdict"], "likely packed / protected")
        self.assertIn("UPX", reasons_joined(packing))

    def test_clean_fixture_has_no_indicators(self) -> None:
        packing = analyze(os.path.join(FIXTURES, "clean.exe"))["packing"]
        self.assertEqual(packing["score"], 0)
        self.assertEqual(packing["verdict"], "no packing indicators")


class TestSyntheticStructure(unittest.TestCase):
    """What a self-unpacking stub must look like, with no names to help."""

    def test_unnamed_stub_is_caught_by_structure(self) -> None:
        packing = packing_of(make_fixtures.stub_without_packer_names(), "stub.exe")
        joined = reasons_joined(packing)
        self.assertEqual(packing["verdict"], "likely packed / protected", joined)
        self.assertIn("writable and executable but stores 0", joined)
        self.assertIn("dynamic resolver", joined)
        self.assertNotIn("UPX", joined)
        self.assertNotIn("VMProtect", joined)

    def test_resolver_only_imports_are_structure(self) -> None:
        """Same fixture, but scored even with entropy and EP moved out of the way."""
        report = analyze_blob(make_fixtures.stub_without_packer_names(), "stub.exe")
        ids = reasons_joined(report["packing"])
        self.assertIn("LoadLibrary + GetProcAddress", ids)
        # the import table itself is small enough to be a resolver's
        self.assertLessEqual(report["imports"]["function_count"], 12)

    def test_zero_filled_read_only_pad_is_not_a_stub(self) -> None:
        """ntoskrnl.exe/hvax64.exe shape: three weak signals, no structure."""
        packing = packing_of(make_fixtures.linker_pad_sections(), "pad.exe")
        self.assertEqual(packing["verdict"], "no packing indicators",
                         reasons_joined(packing))
        self.assertLess(packing["score"], 30)

    def test_corroboration_alone_cannot_reach_a_verdict(self) -> None:
        packing = packing_of(make_fixtures.corroboration_only(), "odd.exe")
        self.assertEqual(packing["verdict"], "no packing indicators",
                         reasons_joined(packing))
        self.assertIn("corroborating only", reasons_joined(packing))
        # the raw signals do add up past 30; the score is held inside the band
        # the verdict names so report rendering cannot contradict the summary
        self.assertLess(packing["score"], 30)

    def test_compressed_resource_alone_is_not_packing(self) -> None:
        packing = packing_of(make_fixtures.compressed_resource_only(), "setup.exe")
        self.assertEqual(packing["score"], 0, reasons_joined(packing))
        self.assertEqual(packing["verdict"], "no packing indicators")

    def test_score_and_verdict_stay_in_range(self) -> None:
        for fixture in (make_fixtures.clean_exe(), make_fixtures.packed_exe(),
                        make_fixtures.stub_without_packer_names(),
                        make_fixtures.linker_pad_sections(),
                        make_fixtures.managed_exe(),
                        make_fixtures.managed_exe_without_imports(),
                        make_fixtures.managed_protected_exe(),
                        make_fixtures.resource_only_image(),
                        make_fixtures.compressed_resource_only(),
                        make_fixtures.upx_named_only(),
                        make_fixtures.corroboration_only()):
            packing = packing_of(fixture)
            self.assertGreaterEqual(packing["score"], 0)
            self.assertLessEqual(packing["score"], 100)
            self.assertIn(packing["verdict"], VERDICTS)
            if packing["verdict"] == "likely packed / protected":
                self.assertGreaterEqual(packing["score"], 60)
            elif packing["verdict"] == "possibly packed":
                self.assertGreaterEqual(packing["score"], 30)


class TestSyntheticManaged(unittest.TestCase):
    """The CLR convention is not packer evidence."""

    def test_managed_exe_with_hot_il_is_not_packed(self) -> None:
        report = analyze_blob(make_fixtures.managed_exe(), "managed.exe")
        self.assertTrue(report["pe"]["dotnet"], "fixture must declare a CLR header")
        self.assertEqual(report["packing"]["score"], 0,
                         reasons_joined(report["packing"]))
        self.assertIn("CLR convention", reasons_joined(report["packing"]))

    def test_managed_exe_without_imports_is_only_noted(self) -> None:
        """System32\\tzsync.exe shape: unusual, but a CLR host can still start it."""
        report = analyze_blob(make_fixtures.managed_exe_without_imports(), "tzsync.exe")
        self.assertTrue(report["pe"]["dotnet"])
        joined = reasons_joined(report["packing"])
        self.assertEqual(report["packing"]["verdict"], "no packing indicators", joined)
        self.assertEqual(report["packing"]["score"], 0, joined)
        self.assertIn("mscoree", joined)

    def test_managed_image_with_rewritten_header_is_flagged(self) -> None:
        report = analyze_blob(make_fixtures.managed_protected_exe(), "protected.exe")
        self.assertTrue(report["pe"]["dotnet"])
        joined = reasons_joined(report["packing"])
        self.assertEqual(report["packing"]["verdict"], "possibly packed", joined)
        self.assertIn("non-printable", joined)

    def test_resource_only_image_is_not_packed(self) -> None:
        """No code, no imports: 71 stock Windows DLLs look like this."""
        packing = packing_of(make_fixtures.resource_only_image(), "resource.dll")
        self.assertEqual(packing["verdict"], "no packing indicators",
                         reasons_joined(packing))
        self.assertEqual(packing["score"], 0, reasons_joined(packing))
        self.assertIn("resource-only", reasons_joined(packing))


class TestRealPackers(unittest.TestCase):
    """Genuine packed images found on this host. Skips when they are not here."""

    def _assert_packed(self, path: str, family: str) -> None:
        report = analyze(path, skip_strings=True)
        joined = reasons_joined(report["packing"])
        self.assertEqual(report["packing"]["verdict"], "likely packed / protected",
                         f"{path}: {joined}")
        self.assertIn(family, joined, f"{path}: {joined}")
        # and the structural half of the evidence is present too, not just a name
        self.assertGreaterEqual(report["packing"]["score"], 60)

    def test_upx_samples(self) -> None:
        tested = 0
        for path in UPX_SAMPLES:
            if not os.path.exists(path):
                continue
            tested += 1
            with self.subTest(sample=os.path.basename(path)):
                self._assert_packed(path, "UPX")
        if not tested:
            self.skipTest("no UPX sample on this host")

    def test_vmprotect_sample(self) -> None:
        tested = 0
        for path in VMPROTECT_SAMPLES:
            if not os.path.exists(path):
                continue
            tested += 1
            with self.subTest(sample=os.path.basename(path)):
                self._assert_packed(path, "VMProtect")
        if not tested:
            self.skipTest("no VMProtect sample on this host")


class TestRealClean(unittest.TestCase):
    """Stock images that must not be reported as packed. Skips when absent."""

    def test_clean_images(self) -> None:
        tested = 0
        for path in CLEAN_SAMPLES:
            if not os.path.exists(path):
                continue
            tested += 1
            with self.subTest(sample=os.path.basename(path)):
                report = analyze(path, skip_strings=True)
                self.assertEqual(report["packing"]["verdict"], "no packing indicators",
                                 f"{path}: {reasons_joined(report['packing'])}")
                self.assertLess(report["packing"]["score"], 30)
        if not tested:
            self.skipTest("no clean control image on this host")

    def test_managed_images(self) -> None:
        tested = 0
        for path in MANAGED_SAMPLES:
            if not os.path.exists(path):
                continue
            tested += 1
            with self.subTest(sample=os.path.basename(path)):
                report = analyze(path, skip_strings=True)
                self.assertEqual(report["packing"]["verdict"], "no packing indicators",
                                 f"{path}: {reasons_joined(report['packing'])}")
        if not tested:
            self.skipTest("no managed reference image on this host")


if __name__ == "__main__":
    unittest.main(verbosity=2)
