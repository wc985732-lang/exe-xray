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
