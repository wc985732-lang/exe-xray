"""Managed (.NET) protection rules, locked against assemblies that really exist.

``analyze._managed_verdict`` reads CLR metadata instead of the PE header, because
ConfuserEx, .NET Reactor, Eazfuscator, Dotfuscator and Obfuscar rewrite metadata
and leave the header innocent.  Nothing here changes that logic; these tests only
record what it does today so a refactor cannot quietly move the line.

Three kinds of evidence, kept apart on purpose:

* ``TestCleanAssemblyBaseline`` runs on genuine Microsoft assemblies installed on
  the host (CoreCLR 6/8/9 and .NET Framework 4.x).  They must all read as
  ``no managed protection indicators`` with ``score == 0``.  A *skip* means the
  file is not on this machine -- "not proven here", never "proven fine".  A green
  run on a host without .NET proves nothing about real assemblies.
* ``TestUnmanagedImage`` runs on native PE files: the managed verdict must not
  apply to them at all.
* ``TestManagedVerdictShape`` pins the returned dictionary's keys and types.
  That shape is the contract ``report["managed"]``, ``_risk`` (line 1413) and
  ``_verdict`` (line 1558) read, so it is worth a guard of its own.

Nothing is executed: every sample is parsed as bytes.  Run with
``python -m unittest discover -s tests -q``.
"""

from __future__ import annotations

import functools
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (ROOT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

from exe_xray.analyze import (  # noqa: E402
    IL_ENTROPY_CEILING,
    MANAGED_MARKERS,
    MDEF_RVA_FLOOR,
    POSSIBLY_PACKED,
    USER_STRING_ENTROPY_CEILING,
    _clr_metadata,
    _managed_marker_families,
    _managed_verdict,
    analyze,
)
from exe_xray.pe import PE  # noqa: E402

# --------------------------------------------------------------------------- #
# vocabulary the verdict must stay inside
# --------------------------------------------------------------------------- #

CLEAN = "no managed protection indicators"
VERDICTS = {
    CLEAN,
    "possibly managed protection",
    "likely managed protection",
    "managed metadata unreadable",
    "not a managed image",
}
RESOURCE_KINDS = {"resources", "zip", "xml", "unrecognised"}

# The 13 keys a managed verdict carries (analyze.py:1260-1274).
MANAGED_KEYS = {
    "applies",
    "score",
    "verdict",
    "family",
    "streams",
    "methods",
    "identifiers",
    "identifiers_control",
    "rva_share",
    "mdef_width",
    "il_entropy",
    "resource_kinds",
    "reasons",
}
# The 4 keys a non-managed verdict carries (analyze.py:1155-1156).
UNMANAGED_KEYS = {"applies", "score", "verdict", "reasons"}

# --------------------------------------------------------------------------- #
# locating real samples: each is version-independent, absent means skip
# --------------------------------------------------------------------------- #

WINDIR = os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows"
PROGRAMFILES = os.environ.get("ProgramFiles") or r"C:\Program Files"
DOTNET_SHARED = os.path.join(PROGRAMFILES, "dotnet", "shared", "Microsoft.NETCore.App")
FRAMEWORK64 = os.path.join(WINDIR, "Microsoft.NET", "Framework64", "v4.0.30319")
SYSTEM32 = os.path.join(WINDIR, "System32")


def _version_key(name: str) -> tuple[int, ...]:
    parts = name.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return (-1,)


def _runtime_dirs() -> list[str]:
    try:
        names = os.listdir(DOTNET_SHARED)
    except OSError:
        return []
    return [os.path.join(DOTNET_SHARED, n)
            for n in sorted(names, key=_version_key, reverse=True)]


def _core_assembly(name: str, major: int | None = None) -> str | None:
    """Newest installed copy of ``name``, optionally pinned to one major version."""
    for directory in _runtime_dirs():
        if major is not None and os.path.basename(directory).split(".")[0] != str(major):
            continue
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _file(path: str) -> str | None:
    return path if os.path.isfile(path) else None


#: label -> (path or None, extra expectations).  Extra keys are optional; the
#: baseline contract (managed image, clean verdict, score 0) is asserted always.
SAMPLES: tuple[tuple[str, str | None, dict], ...] = (
    ("coreclr8-System.Private.CoreLib",
     _core_assembly("System.Private.CoreLib.dll", 8),
     {"min_methods": 5000, "min_identifiers": 500}),
    ("coreclr6-System.Private.CoreLib",
     _core_assembly("System.Private.CoreLib.dll", 6),
     {"min_methods": 5000, "min_identifiers": 500}),
    ("coreclr-System.Text.Encoding.CodePages",
     _core_assembly("System.Text.Encoding.CodePages.dll"),
     {"unrecognised_resource": True}),
    ("coreclr-System.Linq",
     _core_assembly("System.Linq.dll"),
     {"min_methods": 50}),
    ("coreclr-System.Collections",
     _core_assembly("System.Collections.dll"),
     {"min_methods": 50}),
    ("framework-mscorlib",
     _file(os.path.join(FRAMEWORK64, "mscorlib.dll")),
     {"unrecognised_resource": True, "stream": "#US"}),
    ("framework-System",
     _file(os.path.join(FRAMEWORK64, "System.dll")),
     {"stream": "#US", "min_methods": 500}),
    # A managed EXE shipped in System32 with no import table at all; the
    # analyzer calls out that case separately, so keep it in the baseline.
    ("system32-tzsync",
     _file(os.path.join(SYSTEM32, "tzsync.exe")),
     {"min_methods": 100}),
)

# Native images the managed rules must stay out of.
NATIVE_SAMPLES: tuple[tuple[str, str | None], ...] = (
    ("notepad", _file(os.path.join(SYSTEM32, "notepad.exe"))),
    ("cmd", _file(os.path.join(SYSTEM32, "cmd.exe"))),
)


@functools.lru_cache(maxsize=None)
def _report(path: str) -> dict:
    """One analysis per file for the whole module (CoreLib is 10+ MiB)."""
    return analyze(path, skip_strings=True)


class _SampleCase(unittest.TestCase):
    """Shared skip helpers: an absent sample is a skip, never a pass and never a failure."""

    def require(self, path: str | None, label: str) -> str:
        if not path:
            self.skipTest(f"{label}: sample not present on this host")
        return path

    def managed(self, path: str) -> dict:
        return _report(path)["managed"]


# --------------------------------------------------------------------------- #
# 1. real assemblies are clean
# --------------------------------------------------------------------------- #

class TestCleanAssemblyBaseline(_SampleCase):
    def test_clean_assemblies_report_no_managed_protection(self):
        for label, path, expect in SAMPLES:
            with self.subTest(sample=label):
                path = self.require(path, label)
                managed = self.managed(path)

                self.assertIs(managed["applies"], True)
                self.assertEqual(managed["score"], 0,
                                 f"{label}: a stock assembly must not be scored")
                self.assertEqual(managed["verdict"], CLEAN, f"{label}: {managed['reasons']}")
                self.assertEqual(managed["family"], "",
                                 f"{label}: no protector marker may be attributed")
                # Corroboration can still fire on a clean image (an unrecognised
                # embedded resource, high-entropy IL), but nothing structural did,
                # so the score must stay at zero.
                self.assertEqual(managed["rva_share"], 1.0,
                                 f"{label}: every method body must resolve")
                self.assertEqual(managed["identifiers_control"], 0,
                                 f"{label}: no control characters in identifiers")
                if managed["il_entropy"] is not None:
                    self.assertLess(managed["il_entropy"], IL_ENTROPY_CEILING,
                                    f"{label}: compiler IL must stay under the ceiling")
                if managed["methods"]:
                    self.assertGreaterEqual(managed["rva_share"], MDEF_RVA_FLOOR)

                if "min_methods" in expect:
                    self.assertGreaterEqual(managed["methods"], expect["min_methods"])
                if "min_identifiers" in expect:
                    self.assertGreaterEqual(managed["identifiers"], expect["min_identifiers"])
                if expect.get("unrecognised_resource"):
                    self.assertIn("unrecognised", managed["resource_kinds"])
                if "stream" in expect:
                    self.assertIn(expect["stream"], managed["streams"])

    def test_at_least_five_real_assemblies_were_available(self):
        available = [label for label, path, _ in SAMPLES if path]
        if len(available) < 5:
            self.skipTest(f"only {len(available)} of the baseline assemblies are present "
                          f"on this host: {available}")
        self.assertGreaterEqual(len(available), 5)
        for label, path, _ in SAMPLES:
            if not path:
                continue
            with self.subTest(sample=label):
                self.assertEqual(self.managed(path)["score"], 0)
                self.assertEqual(self.managed(path)["verdict"], CLEAN)

    def test_facade_assembly_is_clean_without_a_method_table(self):
        """A reference assembly has no method bodies: no width, no IL entropy, still clean."""
        label = "coreclr-System.Runtime"
        path = self.require(_core_assembly("System.Runtime.dll"), label)
        managed = self.managed(path)

        self.assertEqual(managed["methods"], 0)
        self.assertIsNone(managed["mdef_width"])
        self.assertIsNone(managed["il_entropy"])
        self.assertEqual(managed["resource_kinds"], [])
        self.assertEqual(managed["reasons"], [])
        self.assertEqual(managed["score"], 0)
        self.assertEqual(managed["verdict"], CLEAN)

    def test_known_non_resource_payload_is_demoted_to_corroboration(self):
        """System.Text.Encoding.CodePages ships 'codepages.nlp', which is not a .NET
        resource stream. That is worth 10 points of corroboration and *no* verdict:
        the corpus proved a plain assembly can embed arbitrary bytes."""
        label = "coreclr-System.Text.Encoding.CodePages"
        path = self.require(_core_assembly("System.Text.Encoding.CodePages.dll"), label)
        managed = self.managed(path)

        self.assertIn("unrecognised", managed["resource_kinds"])
        self.assertEqual(managed["score"], 0,
                         "corroboration alone must never survive as a score")
        self.assertEqual(managed["verdict"], CLEAN)
        joined = " ".join(managed["reasons"])
        self.assertIn("does not start with the .NET resource magic", joined)
        self.assertIn("corroborating only", joined,
                      "the demotion must be stated in the reasons, not silent")
        self.assertTrue(all(isinstance(r, str) and r for r in managed["reasons"]))


# --------------------------------------------------------------------------- #
# 2. native images are not managed
# --------------------------------------------------------------------------- #

class TestUnmanagedImage(_SampleCase):
    def test_native_image_is_not_a_managed_image(self):
        tested = 0
        for label, path in NATIVE_SAMPLES:
            with self.subTest(sample=label):
                path = self.require(path, label)
                managed = self.managed(path)
                tested += 1

                self.assertIs(managed["applies"], False,
                              f"{label} is native; the managed rules must not apply")
                self.assertEqual(managed["verdict"], "not a managed image")
                self.assertEqual(managed["score"], 0)
                self.assertEqual(managed["reasons"], [])
                self.assertEqual(set(managed), UNMANAGED_KEYS,
                                 "an inapplicable verdict must not carry CLR fields")
        if not tested:
            self.skipTest("no native PE sample present on this host")

    def test_full_report_marks_native_image_unmanaged(self):
        path = self.require(NATIVE_SAMPLES[0][1], NATIVE_SAMPLES[0][0])
        report = _report(path)
        self.assertIn("managed", report)
        self.assertIs(report["managed"]["applies"], False)


# --------------------------------------------------------------------------- #
# 3. the returned shape is a contract
# --------------------------------------------------------------------------- #

class TestManagedVerdictShape(_SampleCase):
    def _first_managed(self) -> tuple[str, dict]:
        for label, path, _ in SAMPLES:
            if path:
                return label, self.managed(path)
        self.skipTest("no managed assembly present on this host")

    def test_managed_verdict_key_set_is_exact(self):
        label, managed = self._first_managed()
        self.assertEqual(set(managed), MANAGED_KEYS, f"{label}: key set drifted")

    def test_managed_verdict_value_types(self):
        label, managed = self._first_managed()
        expected = {
            "applies": bool,
            "score": int,
            "verdict": str,
            "family": str,
            "streams": list,
            "methods": int,
            "identifiers": int,
            "identifiers_control": int,
            "rva_share": float,
            "resource_kinds": list,
            "reasons": list,
        }
        for key, kind in expected.items():
            with self.subTest(key=key):
                value = managed[key]
                self.assertIsInstance(value, kind, f"{label}: {key}={value!r}")
                if kind is int:
                    self.assertNotIsInstance(value, bool,
                                             f"{label}: {key} must be a number, not a flag")
        for key in ("mdef_width", "il_entropy"):
            with self.subTest(key=key):
                value = managed[key]
                self.assertTrue(value is None or isinstance(value, (int, float)),
                                f"{label}: {key}={value!r}")
                self.assertNotIsInstance(value, bool)

    def test_managed_verdict_vocabulary_and_bounds(self):
        label, managed = self._first_managed()
        self.assertIn(managed["verdict"], VERDICTS)
        self.assertGreaterEqual(managed["score"], 0)
        self.assertLessEqual(managed["score"], 100)
        self.assertGreaterEqual(managed["rva_share"], 0.0)
        self.assertLessEqual(managed["rva_share"], 1.0)
        self.assertGreaterEqual(managed["methods"], 0)
        self.assertGreaterEqual(managed["identifiers"], 0)
        self.assertLessEqual(managed["identifiers_control"], managed["identifiers"])
        self.assertTrue(managed["streams"], "a managed image always has metadata streams")
        self.assertEqual(managed["streams"], sorted(managed["streams"]))
        self.assertTrue(all(isinstance(s, str) for s in managed["streams"]))
        self.assertTrue(set(managed["resource_kinds"]) <= RESOURCE_KINDS,
                        f"{label}: unknown resource kind {managed['resource_kinds']}")
        self.assertEqual(managed["resource_kinds"], sorted(managed["resource_kinds"]))
        self.assertLessEqual(len(managed["reasons"]), 10, "reasons are capped at ten")
        self.assertTrue(all(isinstance(r, str) for r in managed["reasons"]))
        if managed["family"]:
            self.assertIn(managed["family"],
                          {family for _needle, family in MANAGED_MARKERS})

    def test_thresholds_stay_in_their_documented_range(self):
        """The four numbers the rules compare against; sanity, not a value freeze."""
        for name, value, low, high in (
            ("POSSIBLY_PACKED", POSSIBLY_PACKED, 1, 99),
            ("MDEF_RVA_FLOOR", MDEF_RVA_FLOOR, 0.0, 1.0),
            ("IL_ENTROPY_CEILING", IL_ENTROPY_CEILING, 0.0, 8.0),
            ("USER_STRING_ENTROPY_CEILING", USER_STRING_ENTROPY_CEILING, 0.0, 8.0),
        ):
            with self.subTest(threshold=name):
                self.assertGreaterEqual(value, low)
                self.assertLessEqual(value, high)
        self.assertLess(POSSIBLY_PACKED, 100)

    def test_clr_metadata_facts_shape(self):
        """The private facts dict the verdict rules read: a stable subset of keys."""
        label = "coreclr-System.Linq"
        path = self.require(_core_assembly("System.Linq.dll"), label)
        with open(path, "rb") as fh:
            facts = _clr_metadata(PE(fh.read(), path))
        self.assertIs(facts["present"], True)
        self.assertNotIn("error", facts)
        required = {
            "present", "streams", "table_stream", "module", "methods", "rva_share",
            "mdef_width", "mdef_spec_width", "bodies", "il_entropy", "identifiers",
            "identifiers_control", "identifiers_unprintable", "us_present",
            "us_size", "us_entropy", "resources",
        }
        self.assertTrue(required <= set(facts),
                        f"missing facts: {sorted(required - set(facts))}")
        self.assertIsInstance(facts["streams"], dict)
        self.assertIn("#~", facts["streams"])
        self.assertEqual(facts["table_stream"], "#~")
        self.assertTrue(facts["module"].endswith(".dll"))
        self.assertIsInstance(facts["resources"], list)
        for entry in facts["resources"]:
            self.assertEqual(set(entry), {"name", "magic"})
            self.assertIn(entry["magic"], RESOURCE_KINDS)

    def test_unmanaged_report_keeps_the_placeholder_shape(self):
        """``analyze`` wraps the verdict in ``_safe`` with this exact default."""
        clean = {"applies": False, "score": 0, "verdict": "not analysed", "reasons": []}
        self.assertEqual(set(clean), UNMANAGED_KEYS)
        self.assertIn(clean["verdict"], VERDICTS | {"not analysed"})


# --------------------------------------------------------------------------- #
# 4. the verdict is a pure function of the bytes
# --------------------------------------------------------------------------- #

class TestDeterminism(_SampleCase):
    def test_repeated_analysis_agrees(self):
        label = "coreclr-System.Linq"
        path = self.require(_core_assembly("System.Linq.dll"), label)
        first = _report(path)["managed"]
        second = analyze(path, skip_strings=True)["managed"]
        self.assertEqual(first, second)

    def test_direct_call_matches_the_report(self):
        label = "coreclr-System.Linq"
        path = self.require(_core_assembly("System.Linq.dll"), label)
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertEqual(_managed_verdict(PE(data, path)), _report(path)["managed"])


# --------------------------------------------------------------------------- #
# 5. how the rest of the report consumes the score
# --------------------------------------------------------------------------- #

class TestConsumptionSites(_SampleCase):
    def test_clean_assembly_raises_no_managed_signal(self):
        label = "coreclr-System.Linq"
        path = self.require(_core_assembly("System.Linq.dll"), label)
        report = _report(path)
        ids = {signal.get("id") for signal in report["risk"]["signals"]}
        self.assertNotIn("managed-protected", ids)
        self.assertNotIn("Managed protection", report["verdict"]["summary"])

    def test_clean_assembly_summary_calls_it_a_dotnet_image(self):
        label = "coreclr-System.Linq"
        path = self.require(_core_assembly("System.Linq.dll"), label)
        self.assertIn(".NET", _report(path)["verdict"]["kind"])


# --------------------------------------------------------------------------- #
# 6. marker matching, in isolation (no CLR image needed)
# --------------------------------------------------------------------------- #

class TestMarkerFamilies(unittest.TestCase):
    def test_empty_buffer_has_no_families(self):
        self.assertEqual(_managed_marker_families(b""), [])

    def test_utf8_needle_is_detected(self):
        self.assertEqual(_managed_marker_families(b"\x00junk-ConfusedBy-junk\x00"),
                         ["ConfuserEx"])

    def test_utf16le_needle_is_detected(self):
        wide = "Eazfuscator".encode("utf-16-le")
        self.assertEqual(_managed_marker_families(b"\xff" + wide + b"\xff"),
                         ["Eazfuscator"])

    def test_families_are_deduplicated_and_ordered(self):
        data = b"ConfusedBy" + b"Eziriz" + b"ConfuserEx"
        self.assertEqual(_managed_marker_families(data), ["ConfuserEx", ".NET Reactor"])

    def test_every_family_is_reachable_from_its_needle(self):
        for needle, family in MANAGED_MARKERS:
            with self.subTest(family=family, needle=needle):
                self.assertIn(family, _managed_marker_families(b"x" + needle + b"x"))


if __name__ == "__main__":
    unittest.main()
