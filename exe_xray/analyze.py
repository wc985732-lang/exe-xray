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
import struct
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

# --------------------------------------------------------------------------- #
# packing evidence weights
# --------------------------------------------------------------------------- #
#
# Every number below is a claim about what a piece of evidence *proves*, in three
# tiers, not a knob tuned until a particular file looked right. The tiers exist
# because the coefficients were validated against real images on this host (see
# NOTES-packing.md): every "corroboration" weight below is a signal for which
# legitimate and packed images measurably overlap, and such a signal must never
# be able to decide on its own.
#
# identity      the file names the tool that produced it. Nothing else in the
#               world writes a section called 'UPX0' or '.vmp1'; those strings
#               exist in the packer's own source and nowhere else. One of these
#               settles the question on its own, hence >= LIKELY_PACKED.
# structure     a property a normal link-and-go build cannot have and a
#               self-unpacking stub must have. One of them is worth a look
#               (POSSIBLY_PACKED) and two of them together are a stub.
# corroboration measured to overlap between legitimate and packed images, so it
#               can only tip a score that already has structure behind it.

PACKER_NAME_EVIDENCE = 60          # a section named after the packer itself
PACKER_MAGIC_EVIDENCE = 30         # the packer's own magic when sections renamed
UNINITIALISED_CODE_EVIDENCE = 30   # writable+executable section with 0 bytes on disk
RESOLVER_ONLY_EVIDENCE = 30        # import table reduced to a dynamic resolver
MUTATED_SECTION_NAME_EVIDENCE = 30  # section name a toolchain cannot emit
NO_IMPORTS_EVIDENCE = 15           # code with no import table and nothing exported
CODE_ENTROPY_EVIDENCE = 25         # executable bytes that cannot be x86 code
ENTRY_NOT_IN_FIRST_EVIDENCE = 15   # entry point outside the first section
FEW_IMPORTS_EVIDENCE = 15          # import table too small for the image size
WRITABLE_CODE_EVIDENCE = 10        # section that is both writable and executable
SPARSE_CODE_EVIDENCE = 10          # code section mostly uninitialised on disk
OVERLAY_EVIDENCE = 10              # most of the file sits after the last section
UNNAMED_SECTION_EVIDENCE = 5       # section with no name at all

POSSIBLY_PACKED = 30
LIKELY_PACKED = 60

# Same 25-export line the risk section already uses to call an image a "library
# image": a DLL that exports an API surface that large is offering services, and
# ntdll.dll (2 523 exports, zero imports, talks to the kernel through syscalls)
# is the extreme case of an image for which an empty import table is normal.
LIBRARY_EXPORT_FLOOR = 25

# Shannon entropy above which a section cannot be ordinary compiler output.
# Measured on this host: 3 999 stock Microsoft images (System32 exe+dll with a
# code section >= 4 KiB) peak at 7.83 bits/byte, median 6.08, p99 6.50; real
# packer payloads on the same host start at 7.34 and sit at 7.9-8.0. The two
# ranges overlap, which is why this is corroboration and not structure: raising
# the constant to separate them would also separate nothing, because there is no
# gap to sit in. The constant stays at the classic 7.2 and the *weight* carries
# the honesty.
ENTROPY_CEILING = 7.2

# "The import table is too small for the image" needs both halves: a small table
# on a small image is just a small program, so the size floor is what makes the
# count meaningful.
FEW_IMPORTS = 12
FEW_IMPORTS_MIN_IMAGE = 64 * 1024

# A packer needs to reach any API after it has decoded the real program; loading
# a module and asking it for a symbol is the whole of that mechanism. Both halves
# present *and* (almost) nothing else in the table is the resolver-stub idiom.
LOADER_APIS = frozenset({
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
})
RESOLVER_APIS = frozenset({"GetProcAddress", "GetProcAddressForCaller"})
# Stub-side bookkeeping that UPX-class compressors import alongside the resolver:
# memory protection for the decoded image, and a way to leave. Their presence
# does not make the import table anything other than a resolver.
STUB_TOLERATED_APIS = frozenset({
    "VirtualProtect", "VirtualAlloc", "VirtualFree", "ExitProcess",
    "TerminateProcess", "GetModuleHandleA", "GetModuleHandleW",
})

# Images that carry their own loader legitimately have no import table; the
# Windows boot manager (winload.exe), the hypervisor and the kernel all read as
# "0 imports" and none of them is packed.
SELF_LOADING_SUBSYSTEMS = frozenset({
    "native", "windows-boot-driver", "windows-boot-application",
    "efi-application", "efi-boot-driver", "efi-runtime-driver",
})

# Positive evidence is evidence too. A cryptographically verified signature and a
# stock Microsoft component location are reasons *not* to shout, so they come off
# the score instead of being printed and ignored.
SIGNATURE_CREDIT = 35
WINDOWS_COMPONENT_CREDIT = 20
WINDOWS_COMPONENT_DIRS = ("system32", "syswow64", "winsxs")


# --------------------------------------------------------------------------- #
# managed (.NET) protection weights
# --------------------------------------------------------------------------- #
#
# The packing score above deliberately excludes managed images: IL is
# high-entropy by construction, a framework image imports one function, and a
# self-unpacking stub's structural marks are all *normal* for a CLR image. That
# exclusion is correct and it leaves a hole, because the protectors that matter
# for .NET (ConfuserEx, .NET Reactor, Eazfuscator, Dotfuscator, Obfuscar) do not
# touch the PE header at all -- they rewrite the CLR metadata. So the header
# stays innocent and the image scores zero.
#
# These rules read the metadata instead, and they use the same three tiers as
# the packer table, for the same reason: a signal that legitimate images also
# produce must never be able to decide on its own.
#
# identity      a name only that tool emits. ConfuserEx injects a custom
#               attribute literally called 'ConfusedBy'; .NET Reactor signs its
#               stub with 'Eziriz'. Nothing else writes those.
# structure     a property a compiler cannot produce: identifiers containing
#               control characters, an embedded managed resource that is not a
#               .NET resource stream, a metadata table whose own method bodies
#               do not resolve. Baseline measured over 2 995 managed images on
#               this host (NOTES-dotnet.md): zero occurrences of each.
# corroboration measured to overlap with legitimate output (ReadyToRun images
#               and obfuscated-but-honest assemblies both push these numbers up),
#               so they can only tip a score that already has structure.

MANAGED_IDENTITY_EVIDENCE = 60      # the protector's own name in the metadata
MANAGED_RENAME_EVIDENCE = 30        # identifiers full of control characters
MANAGED_METADATA_EVIDENCE = 30      # method bodies the metadata itself cannot address
MANAGED_RESOURCE_EVIDENCE = 10      # embedded resource that is not a .NET resource
MANAGED_IL_ENTROPY_EVIDENCE = 15    # IL bytes that cannot be IL
MANAGED_STRING_ENTROPY_EVIDENCE = 15  # user-string heap that cannot be text
MANAGED_STRINGS_STRIPPED_EVIDENCE = 10  # code but not one string literal

# Marker strings, as (needle, family). These are literal identifiers emitted by
# the tools themselves; they are matched in UTF-8 and UTF-16LE because both a
# metadata string heap and a native stub can carry them.
MANAGED_MARKERS = (
    (b"ConfusedBy", "ConfuserEx"),
    (b"ConfuserEx", "ConfuserEx"),
    (b"Eziriz", ".NET Reactor"),
    (b".NET Reactor", ".NET Reactor"),
    (b"Eazfuscator", "Eazfuscator"),
    (b"Dotfuscator", "Dotfuscator"),
    (b"Obfuscar", "Obfuscar"),
    (b"SmartAssembly", "SmartAssembly"),
    (b"BabelObfuscator", "Babel"),
)

# A managed resource stream starts with this magic (BSJB's sibling: the
# .resources header). Protectors that encrypt resources leave a compressed blob
# behind, so the payload no longer starts with it.
DOTNET_RESOURCE_MAGIC = b"\xce\xca\xef\xbe"

# Identifier characters: anything below 0x20 cannot occur in a name a compiler
# emits. Measured baseline over the host corpus: 0 identifiers in 2 995 images.
CONTROL_CHAR_CEILING = 0

# Calibrated on this host (NOTES-dotnet.md, section 3):
#   IL body entropy   clean max 5.85 over 1 153 images -> ceiling 6.6
#   #US entropy       clean max 5.33 over 1 147 images -> ceiling 6.2
IL_ENTROPY_CEILING = 6.6
USER_STRING_ENTROPY_CEILING = 6.2

# Method bodies carry the RVA column at offset 0 of a MethodDef row. Every image
# measured on this host pads the row two bytes past the ECMA-335 layout, so the
# width is *measured* per file (the width whose RVAs land in real sections)
# rather than assumed. Below this share of resolvable RVAs the metadata cannot be
# trusted to describe its own code, which is itself the finding.
MDEF_RVA_FLOOR = 0.90


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
    report["managed"] = _safe(
        lambda: _managed_verdict(pe),
        {"applies": False, "score": 0, "verdict": "not analysed", "reasons": []})
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

def _is_code(sec: dict[str, Any]) -> bool:
    """Mapped executable: the section holds bytes the CPU will run."""
    return "X" in sec["flags"]


def _printable_section_name(name: str) -> bool:
    """Section names are 8 bytes of ASCII chosen by the toolchain.

    '' and '<n>' are this parser's markers for a name that was not there, which
    is a different (weaker) observation than a name full of control bytes.
    """
    return all(0x20 <= ord(ch) <= 0x7E for ch in name)


def _entry_section_index(pe: PE, raw_sections: list[Any]) -> int:
    """Index of the section that contains AddressOfEntryPoint, or -1."""
    for index, sec in enumerate(raw_sections):
        span = max(sec.virtual_size, sec.raw_size, 1)
        if sec.virtual_address <= pe.entry_point < sec.virtual_address + span:
            return index
    return -1


def _packing_verdict(pe: PE, sections: list[dict[str, Any]],
                     imports: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    # Credits that come from identity or structure. A verdict needs one of these:
    # corroboration alone must never be able to call a file packed, however many
    # of those weak signals happen to line up.
    structural = 0

    clr = _safe(pe.dotnet, None) or {}
    managed = bool(clr.get("present"))
    size = len(pe.data)
    subsystem = pe.subsystem_name

    # -- identity: the file tells us who packed it ----------------------- #
    families: dict[str, list[str]] = {}
    for sec in sections:
        family = PACKER_SECTION_MARKERS.get(sec["name"].lower())
        if family:
            families.setdefault(family, []).append(sec["name"])
    for family, names in families.items():
        # One credit per packer, not per section: 'UPX0' and 'UPX1' are one
        # observation seen twice, and summing them let a two-section stub score
        # 80 points on its own.
        listing = ", ".join(repr(n) for n in names)
        score += PACKER_NAME_EVIDENCE
        structural += 1
        reasons.append(
            f"sections named {listing}: only {family} itself uses that name, so the "
            f"image was produced by {family}")

    if b"UPX!" in pe.data and "UPX" not in families:
        score += PACKER_MAGIC_EVIDENCE
        structural += 1
        reasons.append("the 'UPX!' magic string is present although the sections were "
                       "renamed around it")

    # -- structure: what a self-unpacking stub must look like ------------ #
    #
    # An unpack destination must be big enough to hold the decoded program, and
    # the decoded program is by definition at least as large as the compressed
    # body that was expanded into it. So a zero-filled code section only counts
    # as a destination when it is not smaller than the biggest file-backed code
    # section: Oracle VirtualBox's single-page `.rwxpg` scratch region is four
    # kilobytes next to an 800 KiB .text, which cannot become the image.
    biggest_backed_code = max(
        [sec["virtual_size"] for sec in sections
         if _is_code(sec) and sec["raw_size"]] or [0])

    for sec in sections:
        code = _is_code(sec)
        writable = "W" in sec["flags"]
        discardable = "DISCARDABLE" in sec["flags"]
        if (code and writable and not discardable and sec["virtual_size"]
                and not sec["raw_size"]
                and sec["virtual_size"] >= biggest_backed_code):
            # Writable *and* executable is what makes this different from the
            # zero-filled padding sections Microsoft's linker emits ('Pad2' in
            # ntoskrnl.exe and in the Hyper-V hypervisor is executable, read-only
            # and discardable): a stub has to be able to write the decoded image
            # into that memory, and a read-only region could only fault.
            score += UNINITIALISED_CODE_EVIDENCE
            structural += 1
            reasons.append(
                f"section {sec['name']!r} is writable and executable but stores 0 of its "
                f"{sec['virtual_size']} bytes: memory reserved for code that does not "
                f"exist on disk yet")
        elif code and sec["raw_size"] and sec["virtual_size"] > sec["raw_size"] * 4:
            score += SPARSE_CODE_EVIDENCE
            reasons.append(
                f"code section {sec['name']!r} reserves {sec['virtual_size']} bytes but "
                f"stores {sec['raw_size']}: most of it is written at run time")

    if not managed:
        funcs = {fn for lib in (_safe(pe.imports, []) or []) for fn in lib.functions}
        if (funcs & LOADER_APIS and funcs & RESOLVER_APIS
                and len(funcs) <= FEW_IMPORTS and size >= FEW_IMPORTS_MIN_IMAGE
                and not funcs - LOADER_APIS - RESOLVER_APIS - STUB_TOLERATED_APIS):
            score += RESOLVER_ONLY_EVIDENCE
            structural += 1
            reasons.append(
                "the import table is nothing but a dynamic resolver (LoadLibrary + "
                "GetProcAddress): the program looks every other API up after it has "
                "decoded itself")

    if managed and not imports.get("dlls"):
        # Reported, not scored. Microsoft ships managed EXEs with no import table
        # at all (System32\tzsync.exe), so "a managed EXE must import
        # mscoree!_CorExeMain" is a habit, not a law, and a loaded-by-a-CLR-host
        # image looks the same as a rewritten one from the header alone.
        reasons.append(
            "this managed image has no import table: a framework EXE normally imports "
            "mscoree!_CorExeMain, so either it is started by a CLR host or the entry "
            "path was rewritten, and the headers cannot tell which")

    mutated = [sec["name"] for sec in sections
               if sec["name"] and not _printable_section_name(sec["name"])]
    if mutated:
        score += MUTATED_SECTION_NAME_EVIDENCE
        structural += 1
        reasons.append(
            f"section name {mutated[0]!r} contains non-printable bytes: no linker emits "
            f"that, the header was rewritten by a tool that does not follow the format")

    # -- corroboration: measured to overlap, so never decisive ----------- #
    if managed:
        # Managed IL is high-entropy by construction (token streams, blob heaps)
        # and a framework image imports exactly one function by CLR convention.
        # Neither number says anything about packing, so neither is scored; the
        # note is printed so the reader knows it was considered, not missed.
        reasons.append("managed image: code entropy and import count are fixed by the "
                       "CLR convention, so neither is used as packing evidence here")
    else:
        hot = [sec for sec in sections
               if _is_code(sec) and sec["raw_size"] >= 4096
               and sec["entropy"] > ENTROPY_CEILING]
        if hot:
            top = max(hot, key=lambda s: s["entropy"])
            score += CODE_ENTROPY_EVIDENCE
            reasons.append(
                f"executable section {top['name']!r} has entropy {top['entropy']:.2f} "
                f"bits/byte, above anything compiler output reaches on this host "
                f"(max 7.83, median 6.08 over 3 999 stock images)")

        total_funcs = imports.get("function_count", 0)
        has_code = any(_is_code(sec) and sec["raw_size"] for sec in sections)
        if total_funcs == 0 and size > 32 * 1024:
            exports = len(_safe(pe.exports, []) or [])
            if subsystem in SELF_LOADING_SUBSYSTEMS:
                reasons.append(
                    f"no import table, which is normal for a {subsystem} image that "
                    f"carries its own loader")
            elif not has_code:
                # 16 of the 21 stock Windows images the old rule flagged were
                # flagged for having no import table, and most of those are
                # resource-only DLLs: strings, manifests, ETW metadata. They
                # import nothing because they never call anything.
                reasons.append("no import table and no executable section: a "
                               "resource-only image, which calls nothing")
            elif exports >= LIBRARY_EXPORT_FLOOR:
                reasons.append(
                    f"no import table but {exports} exported functions: a bottom-layer "
                    f"library such as ntdll.dll, which reaches the kernel through "
                    f"syscalls instead of imports")
            else:
                score += NO_IMPORTS_EVIDENCE
                reasons.append(
                    "no import table at all in an image that does contain code and "
                    "exports almost nothing: either a stub, or a program with its own "
                    "loader, and the headers cannot tell which")
        elif total_funcs and total_funcs < FEW_IMPORTS and size >= FEW_IMPORTS_MIN_IMAGE:
            score += FEW_IMPORTS_EVIDENCE
            reasons.append(
                f"only {total_funcs} imported functions in a {size // 1024} KiB image "
                f"(packers resolve APIs at runtime)")

    for sec in sections:
        if _is_code(sec) and "W" in sec["flags"]:
            score += WRITABLE_CODE_EVIDENCE
            reasons.append(f"section {sec['name']!r} is both writable and executable")
            break

    entry_index = _entry_section_index(pe, pe.sections)
    if entry_index > 0:
        score += ENTRY_NOT_IN_FIRST_EVIDENCE
        reasons.append(
            f"the entry point is in section {entry_index} "
            f"({pe.sections[entry_index].name!r}), not the first: 90% of the images on "
            f"this host start in section 0 and the exceptions are kernel loaders")

    if any(sec["name"].startswith("<") and sec["name"].endswith(">") for sec in sections):
        score += UNNAMED_SECTION_EVIDENCE
        reasons.append("a section has no name at all")

    _, overlay = pe.overlay()
    if overlay > size * 0.5 and overlay > 4096:
        score += OVERLAY_EVIDENCE
        reasons.append(f"{overlay // 1024} KiB of overlay data after the last section")

    score = min(score, 100)
    if not structural and score >= POSSIBLY_PACKED:
        # Corroboration only: the numbers lined up but nothing structural was
        # found, so the honest answer is that nothing was found. The score is
        # clamped into the band the verdict names, because a report that prints
        # "no packing indicators (score 45/100)" coloured like a warning would be
        # telling two stories at once. This is what keeps genuinely odd but
        # legitimate images out of the suspect bucket (hvax64.exe: one import,
        # entry point in the middle section, 30 points of weak signals).
        reasons.append(
            "the signals above are corroborating only; there is no structural packer "
            "evidence, so this image is not called packed")
        score = min(score, POSSIBLY_PACKED - 1)
    if structural and score >= LIKELY_PACKED:
        verdict = "likely packed / protected"
    elif structural and score >= POSSIBLY_PACKED:
        verdict = "possibly packed"
    else:
        verdict = "no packing indicators"
    return {"score": score, "verdict": verdict, "reasons": reasons[:10]}


# --------------------------------------------------------------------------- #
# CLR metadata
# --------------------------------------------------------------------------- #
#
# A read-only walk of the ECMA-335 metadata tables. Nothing is loaded, resolved
# or executed: the tables are a byte-addressed index into the same buffer the PE
# parser already holds, and every read is bounds-checked against it.
#
# Only the tables this section needs are described, plus the ones that sit before
# MethodDef (their widths are what locate it) and ManifestResource (0x28).

#: Coded index kinds -> (tagged tables, tag bits). The width is 2 or 4 bytes
#: depending on whether the largest tagged table can exceed the tag space.
_CODED_INDEX = {
    "ResolutionScope": ([0x00, 0x1A, 0x23, 0x01], 2),
    "TypeDefOrRef": ([0x02, 0x01, 0x1B], 2),
    "HasConstant": ([0x04, 0x08, 0x17], 2),
    "HasCustomAttribute": ([0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E,
                            0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27,
                            0x28, 0x2A, 0x2C, 0x2B], 5),
    "HasFieldMarshal": ([0x04, 0x08], 1),
    "HasDeclSecurity": ([0x02, 0x06, 0x20], 2),
    "MemberRefParent": ([0x02, 0x01, 0x1A, 0x06, 0x1B], 3),
    "HasSemantics": ([0x14, 0x17], 1),
    "MethodDefOrRef": ([0x06, 0x0A], 1),
    "MemberForwarded": ([0x04, 0x06], 1),
    "Implementation": ([0x26, 0x23, 0x27], 2),
    "CustomAttributeType": ([0x00, 0x00, 0x06, 0x0A, 0x00], 3),
    "TypeOrMethodDef": ([0x02, 0x06], 1),
}

_U2, _U4, _STR, _GUID, _BLOB = "u2", "u4", "s", "g", "b"

#: Table index -> column layout, for the tables this module reads or must skip.
_TABLE_COLUMNS: dict[int, list[tuple[str, Any]]] = {
    0x00: [("Generation", _U2), ("Name", _STR), ("Mvid", _GUID),
           ("EncId", _GUID), ("EncBaseId", _GUID)],
    0x01: [("ResolutionScope", ("c", "ResolutionScope")), ("Name", _STR),
           ("Namespace", _STR)],
    0x02: [("Flags", _U4), ("Name", _STR), ("Namespace", _STR),
           ("Extends", ("c", "TypeDefOrRef")), ("FieldList", ("t", 0x04)),
           ("MethodList", ("t", 0x06))],
    0x03: [("Field", ("t", 0x04))],
    0x04: [("Flags", _U2), ("Name", _STR), ("Signature", _BLOB)],
    0x05: [("Method", ("t", 0x06))],
    0x06: [("RVA", _U4), ("ImplFlags", _U2), ("Flags", _U2), ("Name", _STR),
           ("Signature", _BLOB)],
    0x08: [("Flags", _U2), ("Sequence", _U2), ("Name", _STR)],
    0x09: [("Class", ("t", 0x02)), ("Interface", ("c", "TypeDefOrRef"))],
    0x0A: [("Class", ("c", "MemberRefParent")), ("Name", _STR), ("Signature", _BLOB)],
    0x0B: [("Type", _U2), ("Parent", ("c", "HasConstant")), ("Value", _BLOB)],
    0x0C: [("Parent", ("c", "HasCustomAttribute")),
           ("Type", ("c", "CustomAttributeType")), ("Value", _BLOB)],
    0x0D: [("Parent", ("c", "HasCustomAttribute")), ("Value", _BLOB)],
    0x0E: [("Action", _U2), ("Parent", ("c", "HasDeclSecurity")),
           ("PermissionSet", _BLOB)],
    0x0F: [("PackingSize", _U2), ("ClassSize", _U4), ("Parent", ("t", 0x02))],
    0x10: [("Offset", _U4), ("Field", ("t", 0x04))],
    0x11: [("Signature", _BLOB)],
    0x12: [("Parent", ("t", 0x02)), ("EventList", ("t", 0x14))],
    0x14: [("EventFlags", _U2), ("Name", _STR), ("EventType", ("c", "TypeDefOrRef"))],
    0x15: [("Parent", ("t", 0x02)), ("PropertyList", ("t", 0x17))],
    0x17: [("Flags", _U2), ("Name", _STR), ("Type", _BLOB)],
    0x18: [("Semantics", _U2), ("Method", ("t", 0x06)),
           ("Association", ("c", "HasSemantics"))],
    0x19: [("Class", ("t", 0x02)), ("MethodBody", ("c", "MethodDefOrRef")),
           ("MethodDeclaration", ("c", "MethodDefOrRef"))],
    0x1A: [("Name", _STR)],
    0x1B: [("Signature", _BLOB)],
    0x1C: [("MappingFlags", _U2), ("MemberForwarded", ("c", "MemberForwarded")),
           ("ImportName", _STR), ("ImportScope", ("t", 0x1A))],
    0x1D: [("RVA", _U4), ("Field", ("t", 0x04))],
    0x20: [("HashAlgId", _U4), ("Major", _U2), ("Minor", _U2), ("Build", _U2),
           ("Rev", _U2), ("Flags", _U4), ("PublicKey", _BLOB), ("Name", _STR),
           ("Culture", _STR)],
    0x23: [("Major", _U2), ("Minor", _U2), ("Build", _U2), ("Rev", _U2),
           ("Flags", _U4), ("PublicKeyOrToken", _BLOB), ("Name", _STR),
           ("Culture", _STR), ("HashValue", _BLOB)],
    0x26: [("Flags", _U4), ("Name", _STR), ("HashValue", _BLOB)],
    0x27: [("Flags", _U4), ("TypeDefId", _U4), ("TypeName", _STR),
           ("TypeNamespace", _STR), ("Implementation", ("c", "Implementation"))],
    0x28: [("Offset", _U4), ("Flags", _U4), ("Name", _STR),
           ("Implementation", ("c", "Implementation"))],
    0x29: [("NestedClass", ("t", 0x02)), ("EnclosingClass", ("t", 0x02))],
    0x2A: [("Number", _U2), ("Flags", _U2), ("Owner", ("c", "TypeOrMethodDef")),
           ("Name", _STR)],
    0x2B: [("Method", ("c", "MethodDefOrRef")), ("Instantiation", _BLOB)],
    0x2C: [("Owner", ("t", 0x2A)), ("Constraint", ("c", "TypeDefOrRef"))],
}

_MAX_TABLE = 0x2D


class _Metadata:
    """Row addressing for one metadata root. All reads are bounds-checked."""

    def __init__(self, data: bytes, base: int) -> None:
        self.data = data
        self.base = base
        self.streams: dict[str, tuple[int, int]] = {}
        self.stream_order: list[str] = []
        if data[base:base + 4] != b"BSJB":
            raise ValueError("no metadata signature")
        ver_len = struct.unpack_from("<I", data, base + 12)[0]
        if not 0 < ver_len <= 512:
            raise ValueError("implausible version length")
        p = base + 16 + ver_len
        _flags, count = struct.unpack_from("<HH", data, p)
        p += 4
        for _ in range(min(count, 32)):
            off, size = struct.unpack_from("<II", data, p)
            end = data.find(b"\x00", p + 8, p + 40)
            if end < 0:
                raise ValueError("unterminated stream name")
            name = data[p + 8:end].decode("latin-1", "replace")
            self.streams[name] = (off, size)
            self.stream_order.append(name)
            p = p + 8 + ((len(name) + 4) & ~3)

        self.table_stream = next(
            (t for t in ("#~", "#-") if t in self.streams), "")
        self.heap_widths = {"s": 2, "g": 2, "b": 2}
        self.rowcounts: dict[int, int] = {}
        self.tables: dict[int, tuple[int, int, int]] = {}
        self.mdef_stride = 0
        self.mdef_spec = 0
        if self.table_stream:
            self._tables()

    # -- table geometry ------------------------------------------------- #

    def _tables(self) -> None:
        data = self.data
        off, size = self.streams[self.table_stream]
        o = self.base + off
        heap = data[o + 6]
        self.heap_widths = {"s": 4 if heap & 1 else 2,
                            "g": 4 if heap & 2 else 2,
                            "b": 4 if heap & 4 else 2}
        valid = struct.unpack_from("<Q", data, o + 8)[0]
        p = o + 24
        for i in range(_MAX_TABLE):
            if valid >> i & 1:
                self.rowcounts[i] = struct.unpack_from("<I", data, p)[0]
                p += 4
        self._rowcount_start = p
        self._build()

    def _col_size(self, kind: Any) -> int:
        if kind == _U2:
            return 2
        if kind == _U4:
            return 4
        if kind in self.heap_widths:
            return self.heap_widths[kind]
        if kind[0] == "t":
            return 4 if self.rowcounts.get(kind[1], 0) >= 65536 else 2
        tables, bits = _CODED_INDEX[kind[1]]
        widest = max((self.rowcounts.get(t, 0) for t in tables if t), default=0)
        return 4 if widest >= (1 << (16 - bits)) else 2

    def row_size(self, table: int) -> int:
        return sum(self._col_size(k) for _n, k in _TABLE_COLUMNS.get(table, ()))

    def _build(self) -> None:
        self.tables = {}
        cur = self._rowcount_start
        for i in range(_MAX_TABLE):
            rows = self.rowcounts.get(i, 0)
            if not rows:
                continue
            width = self.row_size(i)
            self.tables[i] = (cur, width, rows)
            cur += width * rows
        self.mdef_spec = self.row_size(0x06)

    def rechain(self, mdef_width: int) -> None:
        self.tables = {}
        cur = self._rowcount_start
        for i in range(_MAX_TABLE):
            rows = self.rowcounts.get(i, 0)
            if not rows:
                continue
            width = mdef_width if i == 0x06 else self.row_size(i)
            self.tables[i] = (cur, width, rows)
            cur += width * rows
        self.mdef_stride = mdef_width

    # -- cells ---------------------------------------------------------- #

    def cell(self, table: int, row: int, column: int) -> int:
        """Value of column ``column`` in ``row`` of ``table``."""
        start, width, rows = self.tables[table]
        if not 0 <= row < rows:
            return 0
        p = start + row * width
        for index, (_name, kind) in enumerate(_TABLE_COLUMNS[table]):
            if index == column:
                size = self._col_size(kind)
                if p + size > len(self.data):
                    return 0
                return (struct.unpack_from("<I", self.data, p)[0] if size == 4
                        else struct.unpack_from("<H", self.data, p)[0])
            p += self._col_size(kind)
        return 0

    def string(self, index: int) -> str:
        if "#Strings" not in self.streams:
            return ""
        off, size = self.streams["#Strings"]
        if not 0 <= index < size:
            return ""
        start = self.base + off + index
        end = self.data.find(b"\x00", start, self.base + off + size)
        if end < 0:
            end = self.base + off + size
        return self.data[start:end].decode("utf-8", "replace")

    def heap(self, name: str) -> bytes:
        if name not in self.streams:
            return b""
        off, size = self.streams[name]
        return self.data[self.base + off: self.base + off + size]


def _rva_resolves(pe: PE, rva: int) -> bool:
    return rva == 0 or pe.rva_to_offset_safe(rva) is not None


def _measure_mdef_width(pe: PE, md: _Metadata) -> tuple[int, float]:
    """Choose the MethodDef row width whose RVA column lands in real sections.

    ECMA-335 fixes this width, but every managed image measured on this host
    carries two bytes more than the specification says (NOTES-dotnet.md §2), and
    the wrong choice turns a method table into noise. Trusting the file over the
    document is the only way to read both kinds of image, and the share of
    resolvable RVAs -- returned here -- says whether either choice worked.
    """
    start, spec, rows = md.tables[0x06]
    data = md.data
    probe = list(range(0, min(rows, 300)))
    if rows > 300:
        probe += list(range(0, rows, max(1, rows // 300)))[:300]
    best_width, best_score, best_share = spec, -1, 0.0
    for width in (spec, spec + 2, spec + 4):
        hits = 0
        for row in probe:
            p = start + row * width
            if p + 4 > len(data):
                continue
            if _rva_resolves(pe, struct.unpack_from("<I", data, p)[0]):
                hits += 1
        if hits > best_score:
            best_width, best_score = width, hits
    good = 0
    for row in range(rows):
        p = start + row * best_width
        if p + 4 > len(data):
            break
        if _rva_resolves(pe, struct.unpack_from("<I", data, p)[0]):
            good += 1
    if rows:
        best_share = good / rows
    return best_width, best_share


def _clr_metadata(pe: PE) -> dict[str, Any]:
    """Parse what the managed-protection rules need, or explain why not."""
    data = pe.data
    rva, _size = pe.dir(14)
    if not rva:
        return {"present": False}
    header = pe.rva_to_offset_safe(rva)
    if header is None or header + 72 > len(data):
        return {"present": True, "error": "CLR header points outside the file"}
    md_rva, md_size = struct.unpack_from("<II", data, header + 8)
    res_rva = struct.unpack_from("<I", data, header + 24)[0]
    base = pe.rva_to_offset_safe(md_rva) if md_rva and md_size else None
    if base is None:
        return {"present": True, "error": "metadata root points outside the file"}

    facts: dict[str, Any] = {"present": True}
    try:
        md = _Metadata(data, base)
    except (ValueError, struct.error, IndexError) as exc:
        facts["error"] = f"metadata root unreadable: {exc}"
        return facts

    facts["streams"] = {n: md.streams[n][1] for n in md.stream_order}
    facts["table_stream"] = md.table_stream
    facts["module"] = md.string(md.cell(0x00, 0, 1)) if 0x00 in md.tables else ""

    # -- method bodies --------------------------------------------------- #
    facts["methods"] = 0
    facts["rva_share"] = 1.0
    if 0x06 in md.tables:
        width, share = _measure_mdef_width(pe, md)
        md.rechain(width)
        facts["mdef_width"] = width
        facts["mdef_spec_width"] = md.mdef_spec
        facts["rva_share"] = round(share, 4)
        start, step, rows = md.tables[0x06]
        facts["methods"] = rows
        sizes: list[int] = []
        il_chunks: list[bytes] = []
        for row in range(rows):
            p = start + row * step
            if p + 4 > len(data):
                break
            method_rva = struct.unpack_from("<I", data, p)[0]
            if not method_rva:
                continue
            body = pe.rva_to_offset_safe(method_rva)
            if body is None or body + 1 >= len(data):
                continue
            first = data[body]
            if first & 3 == 2:                     # tiny header
                size = first >> 2
                sizes.append(size)
                if len(il_chunks) < 400:
                    il_chunks.append(data[body + 1:body + 1 + size])
            elif first & 3 == 3:                   # fat header
                if body + 8 > len(data):
                    continue
                flags = struct.unpack_from("<H", data, body)[0]
                header_bytes = (flags >> 12) * 4
                code_size = struct.unpack_from("<I", data, body + 4)[0]
                if 0 < header_bytes <= 12 and 0 < code_size < (1 << 22):
                    sizes.append(code_size)
                    if len(il_chunks) < 400:
                        il_chunks.append(
                            data[body + header_bytes: body + header_bytes + code_size])
        facts["bodies"] = len(sizes)
        facts["il_entropy"] = (round(entropy(b"".join(il_chunks)), 3)
                               if il_chunks else None)

    # -- identifiers ------------------------------------------------------ #
    names: list[str] = []
    if 0x02 in md.tables:
        _s, _w, typedef_rows = md.tables[0x02]
        for row in range(typedef_rows):
            names.append(md.string(md.cell(0x02, row, 1)))
    if 0x06 in md.tables:
        _s, _w, method_rows = md.tables[0x06]
        for row in range(min(method_rows, 2000)):
            names.append(md.string(md.cell(0x06, row, 3)))
    names = [n for n in names if n]
    facts["identifiers"] = len(names)
    facts["identifiers_control"] = sum(
        1 for n in names if any(ord(ch) < 0x20 for ch in n))
    facts["identifiers_unprintable"] = sum(
        1 for n in names if any(not 0x20 <= ord(ch) <= 0x7E for ch in n))

    # -- user strings ------------------------------------------------------ #
    us = md.heap("#US")
    facts["us_present"] = "#US" in md.streams
    facts["us_size"] = len(us)
    facts["us_entropy"] = round(entropy(us), 3) if us else 0.0

    # -- embedded resources ------------------------------------------------ #
    facts["resources"] = []
    res_base = pe.rva_to_offset_safe(res_rva) if res_rva else None
    if res_base is not None and 0x28 in md.tables:
        _s, _w, rows = md.tables[0x28]
        for row in range(min(rows, 64)):
            offset = md.cell(0x28, row, 0)
            if md.cell(0x28, row, 3):          # implemented elsewhere (linked)
                continue
            p = res_base + offset
            if p + 8 > len(data):
                continue
            payload = data[p + 4: p + 8]
            facts["resources"].append({
                "name": md.string(md.cell(0x28, row, 2)),
                "magic": ("resources" if payload == DOTNET_RESOURCE_MAGIC
                          else "zip" if payload[:2] == b"PK"
                          else "xml" if payload[:1] == b"<"
                          or payload == b"\xef\xbb\xbf<"
                          else "unrecognised"),
            })
    return facts


# --------------------------------------------------------------------------- #
# managed protection verdict
# --------------------------------------------------------------------------- #

def _managed_marker_families(data: bytes) -> list[str]:
    """Protector names found in the file, as UTF-8 or UTF-16LE."""
    found: list[str] = []
    for needle, family in MANAGED_MARKERS:
        if family in found:
            continue
        wide = needle.decode("ascii").encode("utf-16-le")
        if needle in data or wide in data:
            found.append(family)
    return found


def _managed_verdict(pe: PE) -> dict[str, Any]:
    """Score a managed image for protector marks, or say it is clean.

    The packing score deliberately exempts managed images because the CLR
    convention makes its structural numbers meaningless. The exemption is right;
    what it left behind was a claim, made by omission, that nothing about a
    managed image can be judged. These rules judge the metadata instead, and they
    stay quiet on a clean assembly because every one of them is a property a
    compiler does not produce -- measured, not assumed (NOTES-dotnet.md).
    """
    try:
        clr = _clr_metadata(pe)
    except Exception as exc:      # one broken facet must not kill the report
        clr = {"present": True, "error": f"{type(exc).__name__}: {exc}"}
    if not clr.get("present"):
        return {"applies": False, "score": 0,
                "verdict": "not a managed image", "reasons": []}

    score = 0
    reasons: list[str] = []
    structural = 0
    identity = False

    if clr.get("error"):
        reasons.append(f"the CLR metadata could not be read ({clr['error']}): no "
                       f"managed-protection judgement is possible from this file")
        return {"applies": True, "score": 0, "verdict": "managed metadata unreadable",
                "reasons": reasons}

    # -- identity: the protector named itself ---------------------------- #
    families = _managed_marker_families(pe.data)
    if families:
        score += MANAGED_IDENTITY_EVIDENCE
        identity = True
        reasons.append(
            f"the file contains the name(s) {', '.join(families)}: these are the "
            f"protector's own identifiers, which no compiler emits")

    # -- structure: what a compiler cannot produce ----------------------- #
    identifiers = clr.get("identifiers", 0)
    control = clr.get("identifiers_control", 0)
    if identifiers >= 10 and control >= 5 and control / identifiers >= 0.02:
        score += MANAGED_RENAME_EVIDENCE
        structural += 1
        reasons.append(
            f"{control} of {identifiers} type and method names contain control "
            f"characters: a renamer wrote those, a compiler cannot")

    share = clr.get("rva_share", 1.0)
    methods = clr.get("methods", 0)
    if methods >= 20 and share < MDEF_RVA_FLOOR:
        score += MANAGED_METADATA_EVIDENCE
        structural += 1
        reasons.append(
            f"only {share:.0%} of the {methods} method bodies are located by the "
            f"metadata's own RVA column: the table does not describe this image")

    odd_resources = [r for r in clr.get("resources", [])
                     if r.get("magic") == "unrecognised"]
    if odd_resources:
        # Demoted to corroboration after the corpus contradicted the first draft:
        # System.Text.Encoding.CodePages.dll ships 'codepages.nlp', a plain data
        # file that is not a .NET resource stream, and it is not protected. An
        # assembly may embed any bytes it likes, so "not a .NET resource" says
        # nothing on its own; it only means the blob was compressed or encrypted
        # *if* the rest of the evidence already points that way.
        score += MANAGED_RESOURCE_EVIDENCE
        name = odd_resources[0].get("name") or "<unnamed>"
        reasons.append(
            f"embedded resource {name!r} does not start with the .NET resource "
            f"magic: either data the program genuinely embeds, or a resource "
            f"stream that was compressed or encrypted at rest")

    # -- corroboration: overlaps with legitimate output ------------------ #
    il_entropy = clr.get("il_entropy")
    bodies = clr.get("bodies", 0)
    if il_entropy is not None and bodies >= 20 and il_entropy > IL_ENTROPY_CEILING:
        score += MANAGED_IL_ENTROPY_EVIDENCE
        reasons.append(
            f"the {bodies} method bodies reach {il_entropy:.2f} bits/byte, above the "
            f"{IL_ENTROPY_CEILING} ceiling measured for compiler output on this host")

    us_entropy = clr.get("us_entropy", 0.0)
    if clr.get("us_present") and clr.get("us_size", 0) > 64 \
            and us_entropy > USER_STRING_ENTROPY_CEILING:
        score += MANAGED_STRING_ENTROPY_EVIDENCE
        reasons.append(
            f"the user-string heap has entropy {us_entropy:.2f} bits/byte "
            f"(ceiling {USER_STRING_ENTROPY_CEILING}): it holds ciphertext, not text")

    if not clr.get("us_present") and methods >= 200:
        score += MANAGED_STRINGS_STRIPPED_EVIDENCE
        reasons.append(
            f"{methods} methods and not one string literal in the image: string "
            f"encryption moves literals out of #US (weak evidence on its own, "
            f"because facade assemblies also ship without a string heap)")

    score = min(score, 100)
    decided = bool(identity or structural)
    if not decided:
        # Corroboration only, so the honest report is "nothing found" -- and a
        # score above zero would contradict that verdict in the same breath. The
        # clean corpus decided this: a plain .NET assembly reaches 25 on embedded
        # data and high-entropy IL alone, and every clean image must read as
        # untouched (NOTES-dotnet.md §4).
        if score:
            reasons.append(
                "the signals above are corroborating only; nothing structural was "
                "found, so this image is not called protected")
        score = 0

    if not decided:
        verdict = "no managed protection indicators"
    elif score >= LIKELY_PACKED:
        verdict = "likely managed protection"
    elif score >= POSSIBLY_PACKED:
        verdict = "possibly managed protection"
    else:
        verdict = "no managed protection indicators"

    return {
        "applies": True,
        "score": score,
        "verdict": verdict,
        "family": families[0] if families else "",
        "streams": sorted(clr.get("streams") or {}),
        "methods": methods,
        "identifiers": identifiers,
        "identifiers_control": control,
        "rva_share": share,
        "mdef_width": clr.get("mdef_width"),
        "il_entropy": il_entropy,
        "resource_kinds": sorted({r.get("magic", "") for r in clr.get("resources", [])}),
        "reasons": reasons[:10],
    }


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

    managed = report.get("managed") or {}
    if managed.get("score", 0) >= 60:
        # A managed protector rewrites the metadata the analysis above reads
        # (names, literals, method bodies), so the capability picture is no more
        # complete than it is for a packed native image -- but it is also no less
        # certain, because the CLR header is still there to be parsed.
        add("managed-protected", "warn",
            "this managed assembly is protected, so the type and method names above "
            "are whatever the protector chose to keep")
        score += 25

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
    managed = report.get("managed") or {}
    if managed.get("score", 0) >= 30:
        summary += f" Managed protection: {managed['verdict']}."

    return {"kind": head, "summary": summary}
