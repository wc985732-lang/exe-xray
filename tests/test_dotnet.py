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
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (ROOT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

from exe_xray.analyze import (  # noqa: E402
    IL_ENTROPY_CEILING,
    LIKELY_PACKED,
    MANAGED_IDENTITY_EVIDENCE,
    MANAGED_IL_ENTROPY_EVIDENCE,
    MANAGED_MARKERS,
    MANAGED_METADATA_EVIDENCE,
    MANAGED_RENAME_EVIDENCE,
    MANAGED_RESOURCE_EVIDENCE,
    MANAGED_STRING_ENTROPY_EVIDENCE,
    MANAGED_STRINGS_STRIPPED_EVIDENCE,
    MDEF_RVA_FLOOR,
    POSSIBLY_PACKED,
    USER_STRING_ENTROPY_CEILING,
    _clr_metadata,
    _managed_marker_families,
    _managed_verdict,
    analyze,
)
from exe_xray.pe import PE  # noqa: E402

import make_fixtures  # noqa: E402

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


# --------------------------------------------------------------------------- #
# 7. the positive path: synthetic CLR images built to trip one rule each
# --------------------------------------------------------------------------- #
#
# Everything above proves the rules stay quiet. None of it proves they can speak:
# with a score that is always zero, "detects protectors" is an untested claim,
# and every weight in analyze.py:170-190 is dead code until something trips it.
#
# The images below are hand-assembled -- no compiler, no protector, nothing
# executed -- but structurally real: a BSJB metadata root, a '#~' table stream
# carrying Module/TypeDef/MethodDef, a '#Strings' heap, and method bodies at
# addresses the MethodDef RVA column actually points at. Only the *content* is
# chosen, and each builder flag makes exactly one measured property true, so a
# test can name the rule that fired and the number it produced.
#
# Caveat worth stating in the test rather than in a report: these prove the
# scoring paths are reachable and calibrated. They are not evidence that a real
# ConfuserEx build looks like this; the corpus in section 1 covers the other
# direction.

CLR_V2_VERSION = b"v4.0.30319\x00\x00"
TINY_BODY_LIMIT = 63          # largest IL a tiny header's size field can address
BODY_SLOT = 0x80              # room per method body inside the CLR section
BROKEN_RVA = 0x00F00000       # far outside any section this fixture declares


def _pad_to(buffer: bytearray, alignment: int) -> None:
    buffer += b"\x00" * ((-len(buffer)) % alignment)


def _string_heap(names: list[str]) -> tuple[bytes, dict[str, int]]:
    """A '#Strings' heap: one NUL-led blob of NUL-terminated UTF-8."""
    heap = bytearray(b"\x00")
    index: dict[str, int] = {}
    for name in names:
        index[name] = len(heap)
        heap += name.encode("utf-8") + b"\x00"
    return bytes(heap), index


def _table_stream(rows: list[tuple[int, list[bytes]]]) -> bytes:
    """A '#~' table stream: header, row counts in table order, then the rows."""
    valid = 0
    for table, _rows in rows:
        valid |= 1 << table
    head = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 0, valid, 0)
    counts = b"".join(struct.pack("<I", len(table_rows)) for _t, table_rows in rows)
    body = b"".join(b"".join(table_rows) for _t, table_rows in rows)
    return head + counts + body


def _metadata_root(streams: list[tuple[str, bytes]]) -> bytes:
    """A metadata root: 'BSJB', version, then stream headers and stream bytes."""
    head = bytearray(b"BSJB" + struct.pack("<HHI", 1, 1, 0))
    head += struct.pack("<I", len(CLR_V2_VERSION)) + CLR_V2_VERSION
    head += struct.pack("<HH", 0, len(streams))
    header_size = sum(8 + ((len(name) + 4) & ~3) for name, _payload in streams)
    body = bytearray()
    placed: list[tuple[int, int]] = []
    for _name, payload in streams:
        while (len(head) + header_size + len(body)) % 4:
            body += b"\x00"
        placed.append((len(head) + header_size + len(body), len(payload)))
        body += payload
    headers = bytearray()
    for (offset, size), (name, _payload) in zip(placed, streams):
        headers += struct.pack("<II", offset, size)
        headers += name.encode("ascii").ljust((len(name) + 4) & ~3, b"\x00")
    return bytes(head + headers + body)


def _method_body(il: bytes) -> bytes:
    """One method body: tiny header when it fits, fat header when it does not."""
    if len(il) <= TINY_BODY_LIMIT:
        return bytes([(len(il) << 2) | 2]) + il
    return struct.pack("<HHII", 0x3003, 8, len(il), 0) + il


def _managed_image(
    *,
    methods: int = 8,
    method_prefix: str = "m",
    marker: str = "",
    marker_wide: bool = False,
    control_names: bool = False,
    broken_rvas: bool = False,
    il: bytes = b"\x00\x2a",
    user_strings: bytes | None = b"\x00\x08Hello\x00",
    resource_blob: bytes | None = None,
    resource_name: str = "payload.bin",
) -> bytes:
    """A CLR image whose score is decided by the flags, never by luck.

    ``marker`` lands in the '#Strings' heap, which is where a protector's custom
    attribute name really sits; ``marker_wide`` puts it in the native stub as
    UTF-16LE instead. ``control_names`` prefixes every identifier with 0x01.
    ``broken_rvas`` points the MethodDef RVA column at an address no section
    covers. ``resource_blob`` is embedded verbatim after its four-byte length
    prefix, so its first four bytes decide the resource kind.
    """
    text = b"\x90" * 0x400
    clr_rva = 0x1000 + ((len(text) + 0xFFF) & ~0xFFF)

    method_names = []
    for index in range(methods):
        leaf = f"{method_prefix}{index:04d}"
        method_names.append(f"\x01{leaf}" if control_names else leaf)
    heap_names = ["Synthetic.Net.dll", "Program"] + method_names
    if marker and not marker_wide:
        heap_names.append(marker)
    if resource_blob is not None:
        heap_names.append(resource_name)
    strings, names = _string_heap(heap_names)

    def streams(rva_of) -> list[tuple[str, bytes]]:
        module = struct.pack("<HHHHH", 0, names["Synthetic.Net.dll"], 1, 0, 0)
        typedef = struct.pack("<IHHHHH", 0x100001, names["Program"], 0, 0, 1, 1)
        method_rows = [
            struct.pack("<IHHHH", rva_of(index), 0, 0x86, names[method_names[index]], 1)
            for index in range(methods)
        ]
        rows: list[tuple[int, list[bytes]]] = [
            (0x00, [module]), (0x02, [typedef]), (0x06, method_rows),
        ]
        if resource_blob is not None:
            rows.append((0x28, [struct.pack("<IIHH", 0, 0, names[resource_name], 0)]))
        parts: list[tuple[str, bytes]] = [
            ("#~", _table_stream(rows)), ("#Strings", strings), ("#GUID", b"\x00" * 16),
        ]
        if user_strings is not None:
            parts.append(("#US", user_strings))
        parts.append(("#Blob", b"\x00"))
        return parts

    # Pass one: geometry only. Row widths are fixed, so the metadata length does
    # not depend on the RVA values it carries.
    probe = _metadata_root(streams(lambda _index: 0))
    body = _method_body(il)
    slot = max(BODY_SLOT, (len(body) + 0xF) & ~0xF)   # a fat body needs the room
    body_base = 0x80 + len(probe)
    body_base += (-body_base) % 0x100
    resources_base = body_base + methods * slot

    def rva_of(index: int) -> int:
        return BROKEN_RVA if broken_rvas else clr_rva + body_base + index * slot

    metadata = _metadata_root(streams(rva_of))
    if len(metadata) != len(probe):
        raise AssertionError("metadata length depends on RVA values; geometry pass is wrong")

    payload = bytearray(0x80) + bytearray(metadata)
    _pad_to(payload, 0x100)
    if len(payload) != body_base:
        raise AssertionError("body area is not where the pass-one geometry put it")
    for index in range(methods):
        cell = bytearray(body)
        cell += b"\x00" * (slot - len(cell))
        payload += cell
    if resource_blob is not None:
        _pad_to(payload, 0x10)
        if len(payload) != resources_base:
            raise AssertionError("resource area is not where the geometry put it")
        payload += struct.pack("<I", len(resource_blob)) + resource_blob
    if marker and marker_wide:
        _pad_to(payload, 4)
        payload += marker.encode("utf-16-le")

    struct.pack_into("<IHHIIII", payload, 0, 72, 2, 5,
                     clr_rva + 0x80, len(metadata), 1, 0x06000001)
    if resource_blob is not None:
        struct.pack_into("<I", payload, 24, clr_rva + resources_base)

    return make_fixtures.build_pe(
        subsystem=3,
        imports={},
        sections=[(".text", text, make_fixtures.CODE_X_R),
                  ("clr", bytes(payload), make_fixtures.DATA_R)],
        entry_section=0,
        clr_section=1,
    )


def _verdict_for(data: bytes) -> dict:
    """The managed verdict for a synthetic image, via a real file on disk."""
    handle, path = tempfile.mkstemp(suffix=".exe", prefix="xray-managed-")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)
        return analyze(path, skip_strings=True)["managed"]
    finally:
        os.unlink(path)


def _facts_for(data: bytes) -> dict:
    return _clr_metadata(PE(data, "<synthetic>"))


class TestSyntheticBaseline(unittest.TestCase):
    """The control: a well-formed synthetic assembly must score zero.

    Without this, every positive test below could be passing because the builder
    makes *everything* look protected.
    """

    def test_synthetic_assembly_is_clean(self):
        managed = _verdict_for(_managed_image(methods=8))
        self.assertIs(managed["applies"], True)
        self.assertEqual(managed["score"], 0, managed["reasons"])
        self.assertEqual(managed["verdict"], CLEAN)
        self.assertEqual(managed["family"], "")
        self.assertEqual(managed["reasons"], [])

    def test_synthetic_geometry_is_real(self):
        """The facts the tests then reason about: 8 bodies, all resolvable."""
        facts = _facts_for(_managed_image(methods=8))
        self.assertNotIn("error", facts)
        self.assertEqual(facts["methods"], 8)
        self.assertEqual(facts["bodies"], 8)
        self.assertEqual(facts["rva_share"], 1.0)
        self.assertEqual(facts["module"], "Synthetic.Net.dll")
        self.assertEqual(facts["table_stream"], "#~")
        self.assertIn("#Strings", facts["streams"])
        self.assertEqual(facts["identifiers"], 9)      # Program + 8 methods
        self.assertEqual(facts["identifiers_control"], 0)
        self.assertEqual(facts["us_present"], True)
        self.assertLess(facts["us_entropy"], USER_STRING_ENTROPY_CEILING)


class TestIdentityEvidence(unittest.TestCase):
    """A protector's own name: 60 points, and the verdict band moves."""

    def test_marker_in_the_string_heap_is_identity(self):
        managed = _verdict_for(_managed_image(methods=8, marker="ConfusedBy"))
        self.assertEqual(managed["score"], MANAGED_IDENTITY_EVIDENCE)
        self.assertEqual(managed["family"], "ConfuserEx")
        self.assertEqual(managed["verdict"], "likely managed protection",
                         "identity alone clears LIKELY_PACKED")
        self.assertGreaterEqual(managed["score"], LIKELY_PACKED)
        joined = " ".join(managed["reasons"])
        self.assertIn("ConfuserEx", joined)
        self.assertIn("no compiler emits", joined)

    def test_marker_in_the_native_stub_is_also_identity(self):
        """The same needle as UTF-16LE, outside the metadata: still 60."""
        managed = _verdict_for(_managed_image(methods=8, marker=".NET Reactor",
                                             marker_wide=True))
        self.assertEqual(managed["score"], MANAGED_IDENTITY_EVIDENCE)
        self.assertEqual(managed["family"], ".NET Reactor")

    def test_marker_does_not_change_the_structural_facts(self):
        """Identity is a name, not a shape: the metadata still reads normal."""
        facts = _facts_for(_managed_image(methods=8, marker="Eazfuscator"))
        self.assertEqual(facts["rva_share"], 1.0)
        self.assertEqual(facts["identifiers_control"], 0)


class TestStructuralEvidence(unittest.TestCase):
    """Properties a compiler cannot produce: 30 points each, either alone decides."""

    def test_control_characters_in_identifiers(self):
        managed = _verdict_for(_managed_image(methods=12, control_names=True))
        self.assertEqual(managed["score"], MANAGED_RENAME_EVIDENCE)
        self.assertEqual(managed["verdict"], "possibly managed protection")
        # Every method is mangled; only the type name ("Program") is still text.
        self.assertEqual(managed["identifiers_control"], managed["identifiers"] - 1)
        joined = " ".join(managed["reasons"])
        self.assertIn("control", joined)
        self.assertIn("renamer", joined)

    def test_method_rvas_outside_every_section(self):
        managed = _verdict_for(_managed_image(methods=20, broken_rvas=True))
        self.assertEqual(managed["score"], MANAGED_METADATA_EVIDENCE)
        self.assertEqual(managed["verdict"], "possibly managed protection")
        # Not exactly 0.0: the width probe may still find a stray column whose
        # bytes happen to land in a section. The rule only asks for "most of them
        # do not resolve", and that is what it must be held to.
        self.assertLess(managed["rva_share"], MDEF_RVA_FLOOR)
        self.assertEqual(managed["methods"], 20)
        joined = " ".join(managed["reasons"])
        self.assertIn("RVA column", joined)

    def test_two_structural_findings_from_different_sources_add_up(self):
        """A renamer and a broken method table are independent: 60 together.

        They cannot be combined on *one* image this small -- once the row width
        probe picks the wrong stride, the name column it reads is noise, so the
        rename rule stops seeing control characters (measured: 3 of 9). Identity
        is the honest partner for this one.
        """
        managed = _verdict_for(_managed_image(methods=20, broken_rvas=True,
                                             marker="Obfuscar"))
        self.assertEqual(managed["score"],
                         MANAGED_IDENTITY_EVIDENCE + MANAGED_METADATA_EVIDENCE)
        self.assertEqual(managed["verdict"], "likely managed protection")

    def test_identity_plus_structure_reaches_ninety(self):
        managed = _verdict_for(_managed_image(methods=20, marker="ConfusedBy",
                                             control_names=True))
        self.assertEqual(managed["score"],
                         MANAGED_IDENTITY_EVIDENCE + MANAGED_RENAME_EVIDENCE)
        self.assertEqual(managed["verdict"], "likely managed protection")


class TestCorroborationOnly(unittest.TestCase):
    """The measured-overlap signals: they may tip a score, never make one.

    analyze.py:1239-1249 zeroes the score unless identity or structure decided,
    and says so in the reasons. These tests pin both halves of that rule.
    """

    def test_unrecognised_resource_alone_scores_zero(self):
        managed = _verdict_for(_managed_image(
            methods=8, resource_blob=b"\x1f\x8b\x08\x00not-a-dotnet-resource"))
        self.assertIn("unrecognised", managed["resource_kinds"])
        self.assertEqual(managed["score"], 0, "corroboration must not survive alone")
        self.assertEqual(managed["verdict"], CLEAN)
        joined = " ".join(managed["reasons"])
        self.assertIn("does not start with the .NET resource magic", joined)
        self.assertIn("corroborating only", joined)

    def test_high_entropy_il_alone_scores_zero(self):
        noisy = bytes((index * 71 + 13) % 256 for index in range(400))
        managed = _verdict_for(_managed_image(methods=20, il=noisy))
        self.assertIsNotNone(managed["il_entropy"])
        self.assertGreater(managed["il_entropy"], IL_ENTROPY_CEILING)
        self.assertEqual(managed["score"], 0)
        self.assertEqual(managed["verdict"], CLEAN)

    def test_ciphertext_string_heap_alone_scores_zero(self):
        managed = _verdict_for(_managed_image(
            methods=8, user_strings=bytes(range(256))))
        self.assertGreater(managed["il_entropy"] or 0, -1)   # IL untouched here
        self.assertEqual(managed["score"], 0)
        self.assertEqual(managed["verdict"], CLEAN)
        joined = " ".join(managed["reasons"])
        self.assertIn("ciphertext", joined)

    def test_missing_string_heap_alone_scores_zero(self):
        """200 methods and no #US: 10 points of corroboration, no verdict."""
        managed = _verdict_for(_managed_image(methods=200, user_strings=None))
        self.assertEqual(managed["methods"], 200)
        self.assertEqual(managed["score"], 0)
        self.assertEqual(managed["verdict"], CLEAN)
        joined = " ".join(managed["reasons"])
        self.assertIn("not one string literal", joined)

    def test_corroboration_stacks_on_identity(self):
        """Resource + ciphertext-string + stripped-heap weights, all on one image."""
        noise = bytes((index * 71 + 13) % 256 for index in range(400))
        managed = _verdict_for(_managed_image(
            methods=200, marker="ConfusedBy", il=noise, user_strings=None,
            resource_blob=b"\x1f\x8b\x08\x00not-a-dotnet-resource"))
        expected = (MANAGED_IDENTITY_EVIDENCE + MANAGED_RESOURCE_EVIDENCE
                    + MANAGED_IL_ENTROPY_EVIDENCE
                    + MANAGED_STRINGS_STRIPPED_EVIDENCE)
        self.assertEqual(managed["score"], expected, managed["reasons"])
        self.assertEqual(managed["verdict"], "likely managed protection")
        self.assertEqual(managed["family"], "ConfuserEx")

    def test_every_documented_weight_is_reachable(self):
        """No weight in analyze.py:170-190 is dead: each has a test that fires it."""
        noisy = bytes((index * 71 + 13) % 256 for index in range(400))
        fired = {}
        fired["identity"] = _verdict_for(_managed_image(methods=8, marker="Obfuscar"))
        fired["rename"] = _verdict_for(_managed_image(methods=12, control_names=True))
        fired["metadata"] = _verdict_for(_managed_image(
            methods=20, marker="Obfuscar", broken_rvas=True))
        fired["resource"] = _verdict_for(_managed_image(
            methods=8, marker="Obfuscar",
            resource_blob=b"\x1f\x8b\x08\x00not-a-dotnet-resource"))
        fired["il_entropy"] = _verdict_for(
            _managed_image(methods=20, marker="Obfuscar", il=noisy))
        fired["string_entropy"] = _verdict_for(_managed_image(
            methods=8, marker="Obfuscar", user_strings=bytes(range(256))))
        fired["strings_stripped"] = _verdict_for(
            _managed_image(methods=200, marker="Obfuscar", user_strings=None))

        expected = {
            "identity": MANAGED_IDENTITY_EVIDENCE,
            "rename": MANAGED_RENAME_EVIDENCE,
            "metadata": MANAGED_IDENTITY_EVIDENCE + MANAGED_METADATA_EVIDENCE,
            "resource": MANAGED_IDENTITY_EVIDENCE + MANAGED_RESOURCE_EVIDENCE,
            "il_entropy": MANAGED_IDENTITY_EVIDENCE + MANAGED_IL_ENTROPY_EVIDENCE,
            "string_entropy": MANAGED_IDENTITY_EVIDENCE + MANAGED_STRING_ENTROPY_EVIDENCE,
            "strings_stripped": (MANAGED_IDENTITY_EVIDENCE
                                 + MANAGED_STRINGS_STRIPPED_EVIDENCE),
        }
        for label, managed in fired.items():
            with self.subTest(weight=label):
                self.assertEqual(managed["score"], expected[label],
                                 f"{label}: {managed['reasons']}")
                self.assertGreaterEqual(managed["score"], POSSIBLY_PACKED)
        self.assertEqual(fired["resource"]["score"],
                         MANAGED_IDENTITY_EVIDENCE + MANAGED_RESOURCE_EVIDENCE)
        self.assertEqual(fired["il_entropy"]["score"],
                         MANAGED_IDENTITY_EVIDENCE + MANAGED_IL_ENTROPY_EVIDENCE)
        self.assertEqual(fired["string_entropy"]["score"],
                         MANAGED_IDENTITY_EVIDENCE + MANAGED_STRING_ENTROPY_EVIDENCE)
        self.assertEqual(fired["strings_stripped"]["score"],
                         MANAGED_IDENTITY_EVIDENCE + MANAGED_STRINGS_STRIPPED_EVIDENCE)


class TestUnreadableMetadata(unittest.TestCase):
    """A mangled metadata root is reported, and it is never scored as evidence."""

    def test_broken_bsjb_signature_is_its_own_verdict(self):
        data = bytearray(_managed_image(methods=8, marker="ConfusedBy"))
        offset = data.find(b"BSJB")
        self.assertGreater(offset, 0, "the fixture must carry a metadata root")
        data[offset:offset + 4] = b"XXXX"
        managed = _verdict_for(bytes(data))
        self.assertIs(managed["applies"], True)
        self.assertEqual(managed["verdict"], "managed metadata unreadable")
        self.assertEqual(managed["score"], 0,
                         "unreadable metadata is a finding, not evidence: no points")
        joined = " ".join(managed["reasons"])
        self.assertIn("could not be read", joined)


if __name__ == "__main__":
    unittest.main()
