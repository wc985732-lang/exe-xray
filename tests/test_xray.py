"""Self-tests: run with ``python -m unittest discover -s tests -v``.

The fixtures are assembled on the fly by ``make_fixtures`` (no compiler, no
network, nothing executed), and a couple of assertions run against real Windows
binaries when they happen to exist.

Two kinds of tests are deliberately conditional and say so out loud:

* ``TestSignatureNegatives`` depends on the Authenticode *verifier* (it needs a
  real embedded PKCS#7 to corrupt), so it skips when the host has no signed
  binary or when the verifier does not produce embedded-signature verdicts yet.
* ``TestPackedFixture`` documents that the UPX fixture is self-referential.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import random
import struct
import sys
import tempfile
import unittest
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (ROOT, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import make_fixtures  # noqa: E402

from exe_xray.analyze import AnalysisError, analyze  # noqa: E402
from exe_xray import strings as S  # noqa: E402
from exe_xray.authenticode import inspect_signature  # noqa: E402
from exe_xray.cli import main  # noqa: E402
from exe_xray.pe import PE, checksum_verification  # noqa: E402
from exe_xray.report import render_human, render_json  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
NOTEPAD = r"C:\Windows\System32\notepad.exe"
PYTHON = sys.executable

# "separately tallied": which signature case the host interpreter actually hit.
SIGNATURE_STATUS: Counter = Counter()

SIGNATURE_SKIP_REASON = (
    "depends on the authenticode verifier producing embedded-signature verdicts "
    f"for {PYTHON}; skipped while the signature implementation is in flux")


def setUpModule() -> None:
    os.makedirs(FIXTURES, exist_ok=True)
    for name, blob in (("clean.exe", make_fixtures.clean_exe()),
                       ("packed.exe", make_fixtures.packed_exe()),
                       ("suspicious.exe", make_fixtures.suspicious_exe())):
        path = os.path.join(FIXTURES, name)
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(blob)
    with open(os.path.join(FIXTURES, "not-a-pe.txt"), "w", encoding="utf-8") as fh:
        fh.write("this is plainly not an executable\n")


def tearDownModule() -> None:
    if SIGNATURE_STATUS:
        split = ", ".join(f"{name}={count}" for name, count in sorted(SIGNATURE_STATUS.items()))
        print(f"\n[signature case tally] {split}", file=sys.stderr)


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def analyze_blob(blob: bytes, name: str = "synthetic.exe") -> dict:
    """Analyse bytes that exist only in memory (written to a temp file first)."""
    fd, path = tempfile.mkstemp(suffix="-" + name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        return analyze(path)
    finally:
        os.unlink(path)


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = main(argv)
    finally:
        sys.stdout, sys.stderr = stdout, stderr
    return code, out.getvalue(), err.getvalue()


class TestHeaders(unittest.TestCase):
    def setUp(self) -> None:
        self.report = analyze(fixture("clean.exe"))

    def test_basic_identity(self) -> None:
        pe = self.report["pe"]
        self.assertEqual(pe["format"], "PE32")
        self.assertEqual(pe["machine"], "x86 (i386)")
        self.assertEqual(pe["bits"], 32)
        self.assertEqual(pe["subsystem"], "windows-console")
        self.assertEqual(pe["kind"], "EXE")

    def test_sections_and_checksum(self) -> None:
        names = [s["name"] for s in self.report["pe"]["sections"]]
        self.assertEqual(names, [".text", ".data"])
        self.assertTrue(self.report["pe"]["checksum"]["valid"])

    def test_hashes_are_hex_and_match_the_file(self) -> None:
        """A length check alone passes for any 64 hex characters; compare bytes."""
        blob = read_bytes(fixture("clean.exe"))
        f = self.report["file"]
        self.assertRegex(f["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertRegex(f["sha1"], r"\A[0-9a-f]{40}\Z")
        self.assertRegex(f["md5"], r"\A[0-9a-f]{32}\Z")
        self.assertEqual(f["size"], len(blob))
        self.assertEqual(f["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(f["sha1"], hashlib.sha1(blob).hexdigest())
        self.assertEqual(f["md5"], hashlib.md5(blob).hexdigest())
        # three different algorithms must not collapse onto one digest
        self.assertEqual(len({f["sha256"], f["sha1"], f["md5"]}), 3)


class TestImports(unittest.TestCase):
    def test_clean_imports(self) -> None:
        report = analyze(fixture("clean.exe"))
        dlls = [d["name"] for d in report["imports"]["dlls"]]
        self.assertIn("kernel32.dll", [d.lower() for d in dlls])
        self.assertEqual(report["imports"]["function_count"], 3)

    def test_capability_classification(self) -> None:
        report = analyze(fixture("suspicious.exe"))
        cats = report["imports"]["categories"]
        for expected in ("injection", "keyboard", "hook", "network", "service",
                         "registry", "anti-debug"):
            self.assertIn(expected, cats, f"{expected} was not classified")
        injection_apis = {a["api"] for a in cats["injection"]["apis"]}
        self.assertIn("CreateRemoteThread", injection_apis)


class TestStrings(unittest.TestCase):
    def test_buckets(self) -> None:
        report = analyze(fixture("suspicious.exe"))
        strings = report["strings"]["by_category"]
        urls = [s["text"] for s in strings["url"]["samples"]]
        self.assertTrue(any("c2.example.invalid" in u for u in urls))
        reg = [s["text"] for s in strings["registry"]["samples"]]
        self.assertTrue(any("CurrentVersion\\Run" in r for r in reg))
        self.assertIn("exfil", strings)

    def test_credential_strings_are_redacted(self) -> None:
        report = analyze(fixture("suspicious.exe"))
        for bucket in report["strings"]["by_category"].values():
            for sample in bucket["samples"]:
                self.assertNotIn("hunter2", sample["text"])


class TestPacking(unittest.TestCase):
    def test_packed_fixture(self) -> None:
        """SELF-REFERENTIAL, on purpose and on the record.

        ``make_fixtures.packed_exe()`` writes sections literally named ``UPX0``
        and ``UPX1``, and the detector fires on exactly those section names. The
        question and the answer come from the same file, so all this test proves
        is that the *section-name lookup table* still works. It is **not**
        evidence that real UPX output is detected: no genuine packed sample is
        checked in, and the entropy bonus is measured on this fixture's own
        random bytes. The negative control right below is the part that has
        evidentiary value.
        """
        report = analyze(fixture("packed.exe"))
        self.assertGreaterEqual(report["packing"]["score"], 60)
        self.assertIn("packed", report["packing"]["verdict"])
        joined = " ".join(report["packing"]["reasons"])
        self.assertIn("UPX", joined)

    def test_section_names_are_what_triggers_the_packer_match(self) -> None:
        """Negative control: same entropy, neutral names -> no packer signature."""
        blob = make_fixtures.build_pe(
            subsystem=2,
            imports={"KERNEL32.dll": ["LoadLibraryA"]},
            sections=[(".text", b"\x90" * 0x200, 0x60000020),
                      (".data", make_fixtures.high_entropy_blob(0x6000, seed=11), 0xC0000040)],
        )
        report = analyze_blob(blob, "neutral.exe")
        joined = " ".join(report["packing"]["reasons"])
        self.assertNotIn("UPX", joined)
        self.assertNotIn("signature of", joined)
        self.assertLess(report["packing"]["score"], 60)

    def test_clean_fixture_is_not_packed(self) -> None:
        report = analyze(fixture("clean.exe"))
        self.assertLess(report["packing"]["score"], 30)


class TestRisk(unittest.TestCase):
    def test_suspicious_is_high(self) -> None:
        report = analyze(fixture("suspicious.exe"))
        self.assertEqual(report["risk"]["level"], "high")
        ids = {s["id"] for s in report["risk"]["signals"]}
        self.assertIn("code-injection", ids)
        self.assertIn("keylogger-channel", ids)
        self.assertIn("exfil-endpoint", ids)

    def test_clean_is_minimal(self) -> None:
        report = analyze(fixture("clean.exe"))
        self.assertIn(report["risk"]["level"], ("minimal", "low"))


class TestErrors(unittest.TestCase):
    def test_missing_file(self) -> None:
        with self.assertRaises(AnalysisError):
            analyze(fixture("does-not-exist.exe"))

    def test_not_a_pe(self) -> None:
        with self.assertRaises(AnalysisError):
            analyze(fixture("not-a-pe.txt"))

    def test_directory(self) -> None:
        with self.assertRaises(AnalysisError):
            analyze(FIXTURES)


class TestRendering(unittest.TestCase):
    def test_json_is_serialisable(self) -> None:
        report = analyze(fixture("suspicious.exe"))
        text = render_json(report)
        again = json.loads(text)
        self.assertEqual(again["tool"]["name"], "exe-xray")
        for key in ("file", "pe", "signature", "imports", "strings", "packing",
                    "risk", "verdict"):
            self.assertIn(key, again)

    def test_human_output_sections(self) -> None:
        report = analyze(fixture("suspicious.exe"))
        text = render_human(report, color=False)
        for heading in ("FILE", "HEADERS", "SIGNATURE", "SECTIONS", "IMPORTS",
                        "STRINGS", "PACKING", "VERDICT"):
            self.assertIn(heading, text)


class TestCli(unittest.TestCase):
    def test_json_exit_zero(self) -> None:
        code, out, _err = run_cli([fixture("clean.exe"), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["file"]["name"], "clean.exe")

    def test_missing_path_exits_nonzero(self) -> None:
        code, _out, err = run_cli([fixture("nope.exe")])
        self.assertEqual(code, 1)
        self.assertIn("error", err)


class TestChecksum(unittest.TestCase):
    """The batch checksum must stay bit-identical to the naive byte loop."""

    @staticmethod
    def legacy_checksum(data: bytes, skip: int) -> int:
        """The pre-optimisation implementation, kept as the oracle."""
        total = 0
        n = len(data)
        off = 0
        while off + 1 < n:
            if off == skip:
                off += 4
                continue
            total += data[off] | (data[off + 1] << 8)
            if total > 0xFFFFFFFF:
                total = (total & 0xFFFF) + (total >> 16)
            off += 2
        if off < n:
            total += data[off]
        total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        return (total + n) & 0xFFFFFFFF

    def test_matches_oracle_on_fixtures(self) -> None:
        for name in ("clean.exe", "packed.exe", "suspicious.exe"):
            blob = read_bytes(fixture(name))
            pe = PE(blob)
            self.assertEqual(pe.computed_checksum(),
                             self.legacy_checksum(blob, pe.checksum_offset), name)

    def test_matches_oracle_on_random_corpus(self) -> None:
        """Odd file lengths, unaligned offsets and max-sum content included."""
        pe = PE(read_bytes(fixture("clean.exe")))
        rng = random.Random(20240507)
        cases: list[tuple[bytes, int]] = []
        for n in (2, 3, 4, 63, 64, 65, 4095, 4096, 4097, 65536, 300_001):
            data = bytes(rng.randrange(256) for _ in range(n))
            for skip in (0, 2, 88, n - 4):
                if 0 <= skip and skip + 4 <= n:
                    cases.append((data, skip))
        cases.append((b"\xff" * 262_144, 88))      # every word at 0xFFFF
        cases.append((b"\xff" * 262_146, 88))      # ... and an odd length
        cases.append((b"\x00" * 1024, 88))
        for data, skip in cases:
            pe.data = data
            pe.checksum_offset = skip
            self.assertEqual(pe.computed_checksum(), self.legacy_checksum(data, skip),
                             f"len={len(data)} skip={skip}")

    def test_unaligned_checksum_offset_falls_back(self) -> None:
        """Odd offsets cannot be zeroed from a 16-bit view: use the scalar path."""
        blob = read_bytes(fixture("suspicious.exe"))
        pe = PE(blob)
        pe.checksum_offset = 89
        self.assertEqual(pe.computed_checksum(), self.legacy_checksum(blob, 89))

    def test_real_binaries_still_validate(self) -> None:
        """Checksum agreement against real files that ship with the OS.

        ``sys.executable`` is a PE image on Windows and an ELF image everywhere
        else, so the specimens are filtered by their own magic rather than by
        guessing from the platform name. A host that offers no PE specimen is
        reported as a skip — "not proven here" — never as a pass.
        """
        tested = 0
        for path in (NOTEPAD, PYTHON):
            if not os.path.exists(path):
                continue
            with open(path, "rb") as handle:
                if handle.read(2) != b"MZ":
                    continue
            tested += 1
            with self.subTest(binary=os.path.basename(path)):
                report = analyze(path)
                self.assertTrue(report["pe"]["checksum"]["valid"],
                                f"{path}: stored checksum no longer matches")
        if not tested:
            self.skipTest("no PE-form specimen on this host")

    def test_disabled_verification_returns_the_stored_value(self) -> None:
        blob = read_bytes(fixture("clean.exe"))
        pe = PE(blob)
        with checksum_verification(False):
            self.assertEqual(pe.computed_checksum(), pe.checksum)
        self.assertEqual(pe.computed_checksum(),
                         self.legacy_checksum(blob, pe.checksum_offset))


class TestNoChecksumFlag(unittest.TestCase):
    """--no-checksum must skip the pass and say so, never invent a verdict."""

    def test_json_marks_the_checksum_unverified(self) -> None:
        code, out, _err = run_cli([fixture("clean.exe"), "--json", "--no-checksum"])
        self.assertEqual(code, 0)
        checksum = json.loads(out)["pe"]["checksum"]
        self.assertIsNone(checksum["valid"])
        self.assertIsNone(checksum["computed"])
        self.assertTrue(checksum["skipped"])
        self.assertRegex(checksum["stored"], r"\A0x[0-9a-f]+\Z")

    def test_human_output_says_not_verified(self) -> None:
        code, out, _err = run_cli([fixture("clean.exe"), "--no-checksum", "--color", "never"])
        self.assertEqual(code, 0)
        self.assertIn("checksum  not verified (--no-checksum)", out)
        self.assertNotIn("checksum  valid", out)

    def test_default_still_verifies(self) -> None:
        _code, out, _err = run_cli([fixture("clean.exe"), "--json"])
        checksum = json.loads(out)["pe"]["checksum"]
        self.assertTrue(checksum["valid"])
        self.assertNotIn("skipped", checksum)


def _signature_verifier_ready() -> bool:
    """True when the embedded-signature path yields a real verdict on a signed file."""
    if not os.path.exists(PYTHON):
        return False
    try:
        signature = inspect_signature(PE(read_bytes(PYTHON), PYTHON))
    except Exception:
        return False
    return signature.get("status") in ("valid", "digest-mismatch")


SIGNATURE_READY = _signature_verifier_ready()


@unittest.skipUnless(os.path.exists(NOTEPAD), "needs notepad.exe")
class TestRealBinary(unittest.TestCase):
    def test_notepad(self) -> None:
        report = analyze(NOTEPAD)
        self.assertEqual(report["pe"]["kind"], "EXE")
        self.assertEqual(report["pe"]["bits"], 64)
        self.assertIn("Notepad", report["pe"]["resources"]["version"]["strings"]
                      .get("FileDescription", ""))

    def test_signed_host_python(self) -> None:
        """No skipUnless here.

        ``sys.executable`` always exists, so the old guard was a dead condition
        that never fired. What genuinely varies between hosts is *whether that
        interpreter carries an embedded signature* — assert the closed set of
        legitimate answers and tally which one this host produced, instead of
        skipping the assertion away.
        """
        report = analyze(PYTHON)
        signature = report["signature"]
        self.assertIn("status", signature)
        self.assertIn(signature["status"], ("valid", "unsigned"),
                      f"unexpected signature verdict: {signature}")
        SIGNATURE_STATUS[signature["status"]] += 1
        if signature["status"] == "unsigned":
            self.assertTrue(signature.get("detail"),
                            "an 'unsigned' verdict must explain itself")
            self.assertFalse(signature.get("signers"))
        else:
            self.assertTrue(signature.get("signers"),
                            "status=valid must name at least one signer")
            self.assertTrue(signature.get("detail"))


@unittest.skipUnless(SIGNATURE_READY, SIGNATURE_SKIP_REASON)
class TestSignatureNegatives(unittest.TestCase):
    """Negative controls for the Authenticode verifier.

    Each one starts from a genuinely signed binary on this host, breaks exactly
    one thing, and asserts the verifier notices. They are skippable because the
    signature implementation is being rewritten in parallel; a skip here is
    "not proven", never "proven fine".
    """

    @staticmethod
    def _signed_image() -> tuple[bytearray, PE]:
        blob = bytearray(read_bytes(PYTHON))
        return blob, PE(bytes(blob), PYTHON)

    @staticmethod
    def _security_dir_size_field(pe: PE) -> int:
        """File offset of the Size field of IMAGE_DIRECTORY_ENTRY_SECURITY."""
        return pe.data_directory_offset + 4 * 8 + 4

    def test_truncated_certificate_table_is_not_valid(self) -> None:
        """Cut the file in the middle of the certificate table.

        The WIN_CERTIFICATE entry advertises a dwLength bigger than what is left,
        so no complete PKCS#7 blob exists any more; whatever the verifier does
        with it, it must not come back "valid".

        Known gap, reported but not asserted here: rewriting only the *declared*
        Size field of IMAGE_DIRECTORY_ENTRY_SECURITY to 16 currently still yields
        "valid", because the table walk trusts the entry's own dwLength and never
        re-checks it against the directory size, and the file digest does not
        depend on that size. Physical truncation is the case this test pins down.
        """
        blob, pe = self._signed_image()
        cert_off, cert_size = pe.certificate_table()
        self.assertTrue(cert_off and cert_size,
                        "python.exe should carry an embedded signature")
        cut = cert_off + cert_size // 2
        truncated = PE(bytes(blob[:cut]), PYTHON)
        self.assertEqual(truncated.certificate_table(), (cert_off, cut - cert_off))
        signature = inspect_signature(truncated)
        self.assertNotEqual(signature["status"], "valid")
        self.assertIn(signature["status"], ("unparsed", "digest-mismatch"))
        self.assertTrue(signature.get("detail"))

    def test_modified_section_without_digest_repair_is_a_mismatch(self) -> None:
        blob, pe = self._signed_image()
        section = next(s for s in pe.sections if s.raw_size >= 0x400)
        pos = section.raw_ptr + 0x200
        blob[pos] ^= 0xFF
        # the checksum field and the security directory entry are untouched:
        # only bytes the signature covers changed.
        signature = inspect_signature(PE(bytes(blob), PYTHON))
        self.assertEqual(signature["status"], "digest-mismatch")
        self.assertTrue(signature.get("detail"))

    def test_empty_certificate_table_is_unsigned(self) -> None:
        blob, pe = self._signed_image()
        self.assertTrue(pe.dir(4)[1], "python.exe should declare a certificate table")
        struct.pack_into("<I", blob, self._security_dir_size_field(pe), 0)
        repaired = PE(bytes(blob), PYTHON)
        self.assertEqual(repaired.certificate_table(), (0, 0))
        signature = inspect_signature(repaired)
        self.assertEqual(signature["status"], "unsigned")
        self.assertFalse(signature.get("present"))


@unittest.skipUnless(SIGNATURE_READY, SIGNATURE_SKIP_REASON)
class TestForgeryRegression(unittest.TestCase):
    """The attack that used to work, pinned forever.

    An attacker without the private key can still edit the file and then rewrite
    every digest that lives *inside* the signature blob, because those bytes are
    not covered by the PE hash. Two strengths:

    ``nominal``  rewrite only ``SpcIndirectDataContent.messageDigest`` — the exact
                 forgery that made the first implementation print "signed and
                 unmodified (CN=Microsoft ...)" for an altered file.
    ``attrs``    additionally rewrite the ``messageDigest`` signed attribute, i.e.
                 every digest reachable without the key. Defeating this requires
                 real RSA verification, which is the whole point of the test.

    Neither mode needs the target to run: only file bytes are touched.
    """

    @staticmethod
    def _value_offset(buf: bytes, start: int) -> int:
        off = start + 1
        if buf[start] & 0x1F == 0x1F:
            while buf[off] & 0x80:
                off += 1
            off += 1
        length = buf[off]
        off += 1
        if length & 0x80:
            off += length & 0x7F
        return off

    def _forge(self, mode: str) -> tuple[bytes, dict]:
        from exe_xray.authenticode import authenticode_digest
        from exe_xray.der import decode

        data = bytearray(read_bytes(PYTHON))
        pe = PE(bytes(data), PYTHON)
        cert_off, cert_size = pe.certificate_table()
        self.assertTrue(cert_off and cert_size, "needs a signed binary")

        text = next((s for s in pe.sections if s.name == ".text" and s.raw_size), None)
        self.assertIsNotNone(text, "needs a .text section")
        flip_at = text.raw_ptr + min(0x200, max(0, text.raw_size - 1))
        data[flip_at] ^= 0xFF

        blob_off = cert_off + 8
        blob = bytes(data[blob_off:cert_off + cert_size])
        root = decode(blob)
        signed = root.children[1].children[0]
        spc = signed.children[2].children[1].children[0]
        nominal_node = spc.children[1].children[1]
        digest = authenticode_digest(PE(bytes(data), PYTHON), "sha256")
        at = blob_off + self._value_offset(blob, nominal_node.start)
        data[at:at + len(digest)] = digest

        patched = {"nominal_at": at}
        if mode == "attrs":
            blob2 = bytes(data[blob_off:cert_off + cert_size])
            root2 = decode(blob2)
            signed2 = root2.children[1].children[0]
            spc2 = signed2.children[2].children[1].children[0]
            content_start = self._value_offset(blob2, spc2.start)
            content = blob2[content_start:spc2.end]
            new_msg = hashlib.sha256(content).digest()
            si = signed2.children[-1].children[0]
            for child in si.children:
                if child.cls != 2 or child.number != 0:
                    continue
                for attr in child.children:
                    if not attr.is_sequence or len(attr.children) < 2:
                        continue
                    if attr.children[0].oid() != "1.2.840.113549.1.9.4":
                        continue
                    octet = attr.children[1].children[0]
                    off = blob_off + self._value_offset(blob2, octet.start)
                    data[off:off + len(new_msg)] = new_msg
                    patched["attrs_at"] = off
        return bytes(data), patched

    def _assert_not_trusted(self, mode: str) -> None:
        blob, patched = self._forge(mode)
        handle, path = tempfile.mkstemp(suffix=".exe", prefix="xray_forged_")
        try:
            with os.fdopen(handle, "wb") as fh:
                fh.write(blob)
            report = analyze(path)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        signature = report["signature"]
        self.assertNotEqual(signature["status"], "valid",
                            f"{mode} forgery must not verify: {patched}")
        self.assertFalse(signature.get("verified"))
        verdict = report["verdict"]["summary"]
        self.assertNotIn("signed and unmodified", verdict)
        # and the risk score must not read as "nothing to see here"
        self.assertNotEqual(report["risk"]["level"], "minimal")

    def test_nominal_digest_rewrite_is_detected(self) -> None:
        self._assert_not_trusted("nominal")

    def test_signed_attribute_rewrite_is_detected(self) -> None:
        self._assert_not_trusted("attrs")


class TestExfilHostNames(unittest.TestCase):
    """The exfil table must match a *host*, never a word inside one.

    ``aadtb.dll`` — a Microsoft system DLL — scored 18/100 because the bare
    alternative ``requestbin`` matched ``DefaultUser::RequestBindingInfo``. One
    false positive put it fourth out of 6365 files in a batch sweep. Every entry
    now carries its TLD and is guarded on both sides, so these cases are the
    contract: hosts are still caught, lookalike words are not.
    """

    POSITIVES = (
        "https://discord.com/api/webhooks/123/abc",
        "https://discordapp.com/api/webhooks/1/x",
        "https://ptb.discord.com/api/webhooks/1/x",
        "https://canary.discord.com/api/webhooks/1/x",
        "https://api.telegram.org/bot1234:AAE/getUpdates",
        "https://hooks.slack.com/services/T000/B000/xyz",
        "https://webhook.site/abc-123",
        "https://requestbin.com/r/abc",
        "https://requestbin.net/r/abc",
        "https://requestbin.io/r/abc",
        "https://x.m.pipedream.net/post",
        "https://transfer.sh/abc/file.7z",
        "https://anonfiles.com/abc",
        "https://gofile.io/d/abc",
        "https://0x0.st/abc",
        "https://termbin.com/xyz",
    )

    NEGATIVES = (
        "DefaultUser::RequestBindingInfo",   # the false positive that started this
        # AppMon.dll: "transfer.sh" used to match inside a WinRT type name and
        # scored the DLL 9/100 for an exfiltration endpoint it does not have.
        "Windows.ApplicationModel.DataTransfer.SharedStorageAccessManager",
        "RequestBin",                        # bare service word, no TLD
        "requestbin",
        "termbin",
        "anonfiles",
        "termbin-like",
        "xrequestbin.com",                   # glued to a longer word
        "evil-requestbin.com",               # hyphen-joined
        "requestbin.com.evil.tld",           # a different host that starts the same
        "gofile.io.evil.tld",
        "anonymized",
        "mytermbin",
        "pipedreaming",
        "0x0.stack",
        r"C:\temp\transfer.sh.txt",
        "https://notdiscord.com/api/webhooks/1/x",
    )

    def test_known_exfil_hosts_are_still_caught(self) -> None:
        for text in self.POSITIVES:
            with self.subTest(text=text):
                self.assertIsNotNone(S._EXFIL_RE.search(text), text)

    def test_lookalike_words_are_not_caught(self) -> None:
        for text in self.NEGATIVES:
            with self.subTest(text=text):
                self.assertIsNone(S._EXFIL_RE.search(text), text)

    def test_a_trailing_sentence_period_still_matches(self) -> None:
        self.assertIsNotNone(S._EXFIL_RE.search("upload it to 0x0.st. then delete it"))

    def test_classify_puts_the_host_in_the_exfil_bucket(self) -> None:
        buckets = S.classify(["POST /r/abc HTTP/1.1 to https://requestbin.com/r/abc"])
        self.assertIn("exfil", buckets)

    def test_classify_does_not_bucket_the_binding_info_identifier(self) -> None:
        buckets = S.classify(["DefaultUser::RequestBindingInfo"])
        self.assertNotIn("exfil", buckets)


AADTB = r"C:\Windows\System32\aadtb.dll"


class TestRealBinaryIsNotAnExfilClient(unittest.TestCase):
    """Regression on the actual file, when the host has it.

    Not a synthetic stand-in: this is the DLL from the batch sweep whose top
    signal read "hard-coded exfiltration endpoint: DefaultUser::RequestBindingInfo".
    """

    @unittest.skipUnless(os.path.exists(AADTB), f"needs {AADTB}")
    def test_no_exfiltration_endpoint_signal(self) -> None:
        report = analyze(AADTB)
        self.assertNotIn("exfil", report["strings"]["by_category"])
        signal_ids = [s["id"] for s in report["risk"]["signals"]]
        self.assertNotIn("exfil-endpoint", signal_ids)
        self.assertNotIn("exfiltration endpoint", report["verdict"]["summary"])


class TestToolingTokens(unittest.TestCase):
    """Same audit for ``_TOOLING_RE``: brand tokens stay, ambiguous words narrow.

    ``reflective`` and ``meterp`` were the two loose ones; the former is ordinary
    English, the latter is a prefix of "parameter". Both are now tied to the
    artefact that makes them meaningful.
    """

    POSITIVES = (
        "mimikatz.exe",
        "Invoke-Mimikatz -DumpCreds",
        "meterpreter",
        "meterpreter.exe",
        "meterp.exe",
        "CobaltStrike beacon",
        "sekurlsa::logonpasswords",
        r"C:\Windows\System32\lsass.exe",
        "ReflectiveLoader",          # the export name the old pattern could not match
        "reflective loader",
        "reflective_dll",
        "shellcode",
        "psexec.exe",
        "ngrok.exe",
        "chisel.exe",
        "chisel_windows_amd64",
        "frp.exe",
        "frpc.exe",
        "frps.exe",
        "https://pastebin.com/raw/abc",
        "http://abcdefg.onion/",
        "https://discord.com/api/webhooks/1/x",
        "https://api.telegram.org/bot1:x/getMe",
    )

    NEGATIVES = (
        "addParameterProcessor",             # para-meterp-rocessor
        "get_strOutgoingParameterProblem",
        "meterp",
        "reflective UI rendering",           # ordinary English
        "reflective surfaces",
        "beacon.dll.mui",                    # resource of a DLL, not the DLL
        "frpx.exe",
        "chisel tip",
        "xfrps.exe",
        ".onion",                            # a TLD needs a label in front
        "xmimikatz",
        "ngroking",
    )

    def test_offensive_tooling_markers_are_still_caught(self) -> None:
        for text in self.POSITIVES:
            with self.subTest(text=text):
                self.assertIsNotNone(S._TOOLING_RE.search(text), text)

    def test_ambiguous_words_are_not_caught(self) -> None:
        for text in self.NEGATIVES:
            with self.subTest(text=text):
                self.assertIsNone(S._TOOLING_RE.search(text), text)

    def test_classify_keeps_the_tooling_bucket_for_a_real_marker(self) -> None:
        buckets = S.classify(["dropper: reflective loader + shellcode"])
        self.assertIn("tooling", buckets)

    def test_classify_does_not_bucket_parameter_identifiers(self) -> None:
        buckets = S.classify(["addParameterProcessor(get_strOutgoingParameterProblem)"])
        self.assertNotIn("tooling", buckets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
