"""Minimal, dependency-free PE/COFF reader.

Everything here is *read-only parsing of bytes on disk*. Nothing is mapped,
loaded, emulated or executed: the module only ever touches a ``bytes`` object
handed to it by the caller.

Coverage: DOS/COFF/optional headers, sections, data directories, imports,
delay imports, exports, resources (types + VS_VERSIONINFO), debug directory
(PDB path), Rich header, .NET/CLR header, overlay and the Authenticode
certificate table location.
"""

from __future__ import annotations

import struct
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

# Block size for the batch checksum pass: keeps the temporary even/odd slices
# small on huge images without measurable overhead (see PE.computed_checksum).
_CHECKSUM_CHUNK = 4 << 20

# Toggled by ``checksum_verification()``; see ``PE.computed_checksum``.
_VERIFY_CHECKSUM = True


@contextmanager
def checksum_verification(enabled: bool = True) -> Iterator[None]:
    """Temporarily enable/disable the O(file size) PE checksum pass.

    Disabling it is the only way to make a 200 MB+ image analyse in seconds: the
    checksum walks every byte of the file and nothing else in the pipeline is
    that expensive. While disabled, ``PE.computed_checksum()`` returns the stored
    value unchanged, so a caller that compares the two must not read the result
    as a verdict (the CLI replaces the field with an explicit "skipped" marker).
    """
    global _VERIFY_CHECKSUM
    previous = _VERIFY_CHECKSUM
    _VERIFY_CHECKSUM = enabled
    try:
        yield
    finally:
        _VERIFY_CHECKSUM = previous


class PEError(Exception):
    """The input is not a PE image this parser can handle."""


# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #

MACHINES: dict[int, tuple[str, int]] = {
    0x014C: ("x86 (i386)", 32),
    0x8664: ("x64 (AMD64)", 64),
    0x01C0: ("ARM", 32),
    0x01C4: ("ARMv7 Thumb-2", 32),
    0xAA64: ("ARM64", 64),
    0x0200: ("IA-64", 64),
    0x5032: ("RISC-V 32", 32),
    0x5064: ("RISC-V 64", 64),
    0x6264: ("LoongArch 64", 64),
}

SUBSYSTEMS = {
    0: "unknown",
    1: "native",
    2: "windows-gui",
    3: "windows-console",
    5: "os2-console",
    7: "posix-console",
    9: "windows-ce",
    10: "efi-application",
    11: "efi-boot-driver",
    12: "efi-runtime-driver",
    13: "xbox",
    14: "windows-boot-application",
    16: "windows-boot-driver",
}

DLL_CHARACTERISTICS = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

FILE_CHARACTERISTICS = [
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0080, "BYTES_REVERSED_LO"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
]

SECTION_FLAGS = [
    (0x00000020, "CODE"),
    (0x00000040, "IDATA"),
    (0x00000080, "UDATA"),
    (0x02000000, "DISCARDABLE"),
    (0x04000000, "NOT_CACHED"),
    (0x08000000, "NOT_PAGED"),
    (0x10000000, "SHARED"),
    (0x20000000, "X"),
    (0x40000000, "R"),
    (0x80000000, "W"),
]

COMIMAGE_FLAGS = [
    (0x00000001, "ILONLY"),
    (0x00000002, "32BITREQUIRED"),
    (0x00000008, "STRONGNAMESIGNED"),
    (0x00010000, "NATIVE_ENTRYPOINT"),
    (0x00020000, "TRACKDEBUGDATA"),
    (0x00100000, "PREFER_32BIT"),
]

# index -> human name of the optional-header data directories
DATA_DIRECTORIES = [
    "export", "import", "resource", "exception", "security", "basereloc",
    "debug", "architecture", "globalptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "com_descriptor", "reserved",
]

RT_VERSION = 16


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def _need(buf: bytes, off: int, n: int, what: str = "structure") -> None:
    if off < 0 or n < 0 or off + n > len(buf):
        raise PEError(
            f"truncated input: need {n} byte(s) at 0x{off:x} for {what}, "
            f"file holds {len(buf)}"
        )


def _u8(buf: bytes, off: int) -> int:
    _need(buf, off, 1)
    return buf[off]


def _u16(buf: bytes, off: int) -> int:
    _need(buf, off, 2)
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    _need(buf, off, 4)
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    _need(buf, off, 8)
    return struct.unpack_from("<Q", buf, off)[0]


def flag_names(value: int, table: list[tuple[int, str]]) -> list[str]:
    return [name for bit, name in table if value & bit]


def _cstring(buf: bytes, off: int, limit: int = 4096) -> str:
    """Read a NUL-terminated byte string, bounded by ``limit`` bytes."""
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off, min(len(buf), off + limit))
    if end < 0:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# data classes
# --------------------------------------------------------------------------- #

@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def flags(self) -> list[str]:
        return flag_names(self.characteristics, SECTION_FLAGS)

    @property
    def raw_end(self) -> int:
        return self.raw_ptr + self.raw_size if self.raw_size else self.raw_ptr

    @property
    def span(self) -> int:
        """Largest of virtual/raw size: what the loader actually maps."""
        return max(self.virtual_size, self.raw_size, 1)


@dataclass
class ImportLib:
    name: str
    functions: list[str] = field(default_factory=list)
    delay: bool = False


@dataclass
class Export:
    name: str
    rva: int
    forwarder: str | None = None
    ordinal: int | None = None


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

class PE:
    """Read-only view over one PE image."""

    def __init__(self, data: bytes, path: str = "<memory>") -> None:
        self.data = data
        self.path = path
        self.warnings: list[str] = []

        self.dos_stub_size = 0
        self.pe_offset = 0
        self.coff_offset = 0
        self.opt_offset = 0
        self.opt_size = 0
        self.is_pe32plus = False
        self.machine = 0
        self.number_of_sections = 0
        self.timestamp = 0
        self.characteristics = 0
        self.sections: list[Section] = []
        self.dirs: list[tuple[int, int]] = [(0, 0)] * 16

        self.entry_point = 0
        self.image_base = 0
        self.section_alignment = 0
        self.file_alignment = 0
        self.size_of_image = 0
        self.size_of_headers = 0
        self.checksum = 0
        self.checksum_offset = 0
        self.subsystem = 0
        self.dll_characteristics = 0
        self.linker_major = 0
        self.linker_minor = 0
        self.os_version = (0, 0)
        self.subsystem_version = (0, 0)
        self.data_directory_offset = 0

        self._parse()

    # -- header ---------------------------------------------------------- #

    def _parse(self) -> None:
        data = self.data
        if len(data) < 0x40:
            raise PEError("file is smaller than a DOS header (64 bytes)")
        if data[:2] != b"MZ":
            raise PEError(
                f"no 'MZ' signature (first bytes: {data[:2]!r}); not a Windows executable"
            )

        e_lfanew = _u32(data, 0x3C)
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            raise PEError(f"DOS header points to PE header at 0x{e_lfanew:x}, outside the file")

        magic4 = data[e_lfanew:e_lfanew + 4]
        if magic4 != b"PE\x00\x00":
            hint = {b"NE": "16-bit New Executable", b"LE": "16-bit Linear Executable",
                    b"LX": "OS/2 LX", b"PE": "corrupt PE header"}.get(magic4[:2])
            raise PEError(
                f"unsupported executable signature {magic4!r}"
                + (f" ({hint})" if hint else "")
            )

        self.dos_stub_size = e_lfanew
        self.pe_offset = e_lfanew
        self.coff_offset = e_lfanew + 4

        (self.machine, self.number_of_sections, self.timestamp, _ptr_sym,
         _n_sym, self.opt_size, self.characteristics) = struct.unpack_from(
            "<HHIIIHH", data, self.coff_offset)

        self.opt_offset = self.coff_offset + 20
        _need(data, self.opt_offset, 2, "optional header magic")
        magic = _u16(data, self.opt_offset)
        if magic == 0x10B:
            self.is_pe32plus = False
        elif magic == 0x20B:
            self.is_pe32plus = True
        else:
            raise PEError(f"unknown optional header magic 0x{magic:04x}")

        opt = self.opt_offset
        self.linker_major = _u8(data, opt + 2)
        self.linker_minor = _u8(data, opt + 3)
        self.entry_point = _u32(data, opt + 16)
        self.image_base = _u64(data, opt + 24) if self.is_pe32plus else _u32(data, opt + 28)
        self.section_alignment = _u32(data, opt + 32)
        self.file_alignment = _u32(data, opt + 36)
        self.os_version = (_u16(data, opt + 40), _u16(data, opt + 42))
        self.subsystem_version = (_u16(data, opt + 48), _u16(data, opt + 50))
        self.size_of_image = _u32(data, opt + 56)
        self.size_of_headers = _u32(data, opt + 60)
        self.checksum_offset = opt + 64
        self.checksum = _u32(data, self.checksum_offset)
        self.subsystem = _u16(data, opt + 68)
        self.dll_characteristics = _u16(data, opt + 70)

        if self.is_pe32plus:
            self.data_directory_offset = opt + 112
            nrva_off = opt + 108
        else:
            self.data_directory_offset = opt + 96
            nrva_off = opt + 92

        number_of_rva = _u32(data, nrva_off)
        number_of_rva = min(number_of_rva, 16)
        dirs: list[tuple[int, int]] = []
        for i in range(number_of_rva):
            off = self.data_directory_offset + i * 8
            if off + 8 > len(data):
                break
            dirs.append((_u32(data, off), _u32(data, off + 4)))
        while len(dirs) < 16:
            dirs.append((0, 0))
        self.dirs = dirs

        # sections
        sec_off = self.opt_offset + self.opt_size
        for i in range(self.number_of_sections):
            off = sec_off + i * 40
            if off + 40 > len(data):
                self.warnings.append(
                    f"section table truncated after {i} of {self.number_of_sections} entries")
                break
            raw_name = data[off:off + 8]
            name = raw_name.split(b"\x00", 1)[0].decode("latin-1", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
            chars = _u32(data, off + 36)
            self.sections.append(Section(name or f"<{i}>", vaddr, vsize, rsize, rptr, chars))

        if self.number_of_sections == 0:
            self.warnings.append("image declares zero sections")
        if self.size_of_headers > len(data):
            self.warnings.append(
                f"SizeOfHeaders 0x{self.size_of_headers:x} exceeds file size")

    # -- address translation --------------------------------------------- #

    def rva_to_offset(self, rva: int) -> int:
        """Translate an RVA to a file offset; raises PEError when unmapped."""
        if rva < 0:
            raise PEError(f"negative RVA 0x{rva:x}")
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.span:
                delta = rva - sec.virtual_address
                if delta >= sec.raw_size:
                    raise PEError(
                        f"RVA 0x{rva:x} falls in uninitialised part of section {sec.name}")
                off = sec.raw_ptr + delta
                if off >= len(self.data):
                    raise PEError(f"RVA 0x{rva:x} maps past end of file")
                return off
        if rva < self.size_of_headers and rva < len(self.data):
            return rva
        raise PEError(f"RVA 0x{rva:x} is not mapped by any section")

    def rva_to_offset_safe(self, rva: int) -> int | None:
        try:
            return self.rva_to_offset(rva)
        except PEError:
            return None

    def read_rva_string(self, rva: int, limit: int = 4096) -> str:
        try:
            off = self.rva_to_offset(rva)
        except PEError:
            return ""
        return _cstring(self.data, off, limit)

    def section_of_rva(self, rva: int) -> Section | None:
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.span:
                return sec
        return None

    # -- convenience header facts ---------------------------------------- #

    @property
    def arch(self) -> str:
        return MACHINES.get(self.machine, (f"machine 0x{self.machine:04x}", 0))[0]

    @property
    def bits(self) -> int:
        return 64 if self.is_pe32plus else 32

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEMS.get(self.subsystem, f"subsystem {self.subsystem}")

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    @property
    def dll_flags(self) -> list[str]:
        return flag_names(self.dll_characteristics, DLL_CHARACTERISTICS)

    @property
    def file_flags(self) -> list[str]:
        return flag_names(self.characteristics, FILE_CHARACTERISTICS)

    def dir(self, index: int) -> tuple[int, int]:
        return self.dirs[index] if index < len(self.dirs) else (0, 0)

    # -- checksum --------------------------------------------------------- #

    def computed_checksum(self) -> int:
        """Standard PE image checksum (checksum field treated as zero).

        Performance: the textbook loop reads two bytes at a time from Python and
        used to dominate the whole run on big images (166 s of the 232 s it takes
        to look at a 220 MiB MRT.exe). The fast path below uses the identity

            sum of 16-bit little-endian words
              == sum(bytes at even offsets) + 256 * sum(bytes at odd offsets)

        so the whole file can be summed with ``sum()`` over ``bytes`` slices,
        which runs in C over cached small ints. Both sums are exact and the carry
        fold is order-independent, so the result is bit-identical to
        ``_computed_checksum_scalar`` (``tests/test_xray.py`` proves it against
        the old loop on a randomised corpus and against the stored checksums of
        real Windows binaries). Chunking keeps peak memory at a few MiB.
        """
        if not _VERIFY_CHECKSUM:
            # Caller asked to skip verification: return the stored value so that
            # callers comparing the two numbers do not invent a verdict. The CLI
            # overwrites the field with an explicit "skipped" marker.
            return self.checksum

        data = self.data
        n = len(data)
        skip = self.checksum_offset
        if n < 2 or skip % 2 or skip + 4 > n:
            # Odd checksum offsets (never produced by a real linker) cannot be
            # expressed as two whole words: fall back to the byte loop.
            return self._computed_checksum_scalar()

        total = 0
        for start in range(0, n, _CHECKSUM_CHUNK):
            block = data[start:start + _CHECKSUM_CHUNK]
            total += sum(block[0::2]) + (sum(block[1::2]) << 8)

        # the checksum DWORD is treated as zero; subtract what it contributed
        total -= (data[skip] | (data[skip + 1] << 8)) + (data[skip + 2] | (data[skip + 3] << 8))

        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return (total + n) & 0xFFFFFFFF

    def _computed_checksum_scalar(self) -> int:
        """Byte-at-a-time reference: big-endian hosts and odd checksum offsets."""
        data = self.data
        total = 0
        n = len(data)
        off = 0
        skip = self.checksum_offset
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

    # -- imports ----------------------------------------------------------- #

    def imports(self) -> list[ImportLib]:
        rva, size = self.dir(1)
        if not rva:
            return []
        return self._read_import_descriptors(rva, delay=False)

    def delay_imports(self) -> list[ImportLib]:
        rva, size = self.dir(13)
        if not rva:
            return []
        return self._read_import_descriptors(rva, delay=True)

    def _read_import_descriptors(self, rva: int, delay: bool) -> list[ImportLib]:
        libs: list[ImportLib] = []
        ptr_size = 8 if self.is_pe32plus else 4
        thunk_fmt = "<Q" if self.is_pe32plus else "<I"
        pointer_mask = (1 << (ptr_size * 8 - 1))
        desc_size = 32 if delay else 20

        base = self.rva_to_offset_safe(rva)
        if base is None:
            self.warnings.append(
                f"{'delay ' if delay else ''}import directory RVA 0x{rva:x} is unmapped")
            return []

        for i in range(1024):
            off = base + i * desc_size
            if off + desc_size > len(self.data):
                break
            if delay:
                attrs = _u32(self.data, off)
                name_field = _u32(self.data, off + 4)
                int_field = _u32(self.data, off + 16)
                if attrs == 0 and name_field == 0:
                    break
                if not attrs & 1:  # old-style: fields are VAs
                    name_field = name_field - self.image_base if name_field else 0
                    int_field = int_field - self.image_base if int_field else 0
                name_rva, thunk_rva = name_field, int_field
                if not thunk_rva:
                    thunk_rva = _u32(self.data, off + 12)
                    if not attrs & 1 and thunk_rva:
                        thunk_rva -= self.image_base
            else:
                oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", self.data, off)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                thunk_rva = oft or ft
            if not name_rva:
                continue

            dll = self.read_rva_string(name_rva).strip()
            if not dll:
                continue
            # Guard against garbage: DLL names are short ASCII filenames.
            if len(dll) > 260 or any(ord(c) < 0x20 for c in dll):
                self.warnings.append(f"dropped odd import module name at descriptor {i}")
                break

            funcs: list[str] = []
            toff = self.rva_to_offset_safe(thunk_rva) if thunk_rva else None
            if toff is not None:
                for j in range(20000):
                    pos = toff + j * ptr_size
                    if pos + ptr_size > len(self.data):
                        break
                    value = struct.unpack_from(thunk_fmt, self.data, pos)[0]
                    if value == 0:
                        break
                    if value & pointer_mask:
                        funcs.append(f"#{value & 0xFFFF}")
                        continue
                    hint_name = self.rva_to_offset_safe(value & 0x7FFFFFFF)
                    if hint_name is None or hint_name + 2 >= len(self.data):
                        funcs.append(f"<bad thunk 0x{value:x}>")
                        continue
                    funcs.append(_cstring(self.data, hint_name + 2, 512) or "<empty>")
            libs.append(ImportLib(dll, funcs, delay))

        return libs

    # -- exports ----------------------------------------------------------- #

    def exports(self) -> list[Export]:
        rva, size = self.dir(0)
        if not rva:
            return []
        base = self.rva_to_offset_safe(rva)
        if base is None:
            self.warnings.append("export directory is unmapped")
            return []
        try:
            (_chars, _ts, _maj, _min, name_rva, ordinal_base, n_funcs, n_names,
             addr_funcs, addr_names, addr_ordinals) = struct.unpack_from(
                "<IIHHIIIIIII", self.data, base)
        except struct.error:
            self.warnings.append("export directory is truncated")
            return []

        n_funcs = min(n_funcs, 65536)
        n_names = min(n_names, 65536)
        dll_name = self.read_rva_string(name_rva) if name_rva else ""
        f_off = self.rva_to_offset_safe(addr_funcs)
        n_off = self.rva_to_offset_safe(addr_names)
        o_off = self.rva_to_offset_safe(addr_ordinals)
        if f_off is None:
            return []

        func_rvas: list[int] = []
        for i in range(n_funcs):
            pos = f_off + i * 4
            if pos + 4 > len(self.data):
                break
            func_rvas.append(_u32(self.data, pos))

        out: list[Export] = []
        seen: dict[int, Export] = {}
        if n_off and o_off:
            for i in range(n_names):
                if n_off + i * 4 + 4 > len(self.data) or o_off + i * 2 + 2 > len(self.data):
                    break
                n_rva = _u32(self.data, n_off + i * 4)
                idx = _u16(self.data, o_off + i * 2)
                if idx >= len(func_rvas):
                    continue
                f_rva = func_rvas[idx]
                name = self.read_rva_string(n_rva, 512) or f"#{idx + ordinal_base}"
                forwarder = None
                if rva <= f_rva < rva + size:
                    forwarder = self.read_rva_string(f_rva, 512)
                exp = Export(name, f_rva, forwarder, idx + ordinal_base)
                out.append(exp)
                seen[idx] = exp
        for idx, f_rva in enumerate(func_rvas):
            if idx in seen or f_rva == 0:
                continue
            forwarder = None
            if rva <= f_rva < rva + size:
                forwarder = self.read_rva_string(f_rva, 512)
            out.append(Export(f"#{idx + ordinal_base}", f_rva, forwarder, idx + ordinal_base))

        if dll_name:
            self._export_module = dll_name  # type: ignore[attr-defined]
        return out

    # -- resources --------------------------------------------------------- #

    def resources(self) -> list[dict[str, Any]]:
        rva, size = self.dir(2)
        if not rva:
            return []
        out: list[dict[str, Any]] = []
        self._walk_resource_dir(rva, 0, [], out, budget=[8192])
        return out

    def _walk_resource_dir(self, base_rva: int, rel: int, path: list[Any],
                           out: list[dict[str, Any]], budget: list[int], depth: int = 0) -> None:
        if depth > 8 or budget[0] <= 0:
            return
        dir_off = self.rva_to_offset_safe(base_rva + rel)
        if dir_off is None or dir_off + 16 > len(self.data):
            return
        try:
            (_c, _t, _maj, _min, named, ids) = struct.unpack_from("<IIHHHH", self.data, dir_off)
        except struct.error:
            return
        count = min(named + ids, 4096)
        for i in range(count):
            budget[0] -= 1
            if budget[0] <= 0:
                return
            ent = dir_off + 16 + i * 8
            if ent + 8 > len(self.data):
                return
            name_field = _u32(self.data, ent)
            off_field = _u32(self.data, ent + 4)
            if name_field & 0x80000000:
                str_off = self.rva_to_offset_safe(base_rva + (name_field & 0x7FFFFFFF))
                label: Any = None
                if str_off is not None and str_off + 2 <= len(self.data):
                    ln = _u16(self.data, str_off)
                    raw = self.data[str_off + 2: str_off + 2 + ln * 2]
                    label = raw.decode("utf-16-le", "replace")
                if label is None:
                    label = f"<name@{name_field & 0x7FFFFFFF:08x}>"
            else:
                label = name_field & 0xFFFF

            child = path + [label]
            if off_field & 0x80000000:
                self._walk_resource_dir(base_rva, off_field & 0x7FFFFFFF, child, out, budget,
                                        depth + 1)
                continue
            data_ent = self.rva_to_offset_safe(base_rva + off_field)
            if data_ent is None or data_ent + 16 > len(self.data):
                continue
            data_rva = _u32(self.data, data_ent)
            data_size = _u32(self.data, data_ent + 4)
            codepage = _u32(self.data, data_ent + 8)
            out.append({
                "path": child,
                "size": data_size,
                "codepage": codepage,
                "rva": data_rva,
            })

    def version_info(self) -> dict[str, Any]:
        for entry in self.resources():
            path = entry["path"]
            if len(path) < 2:
                continue
            if path[0] != RT_VERSION and not (isinstance(path[1], int) and path[0] == RT_VERSION):
                if path[0] != RT_VERSION:
                    continue
            off = self.rva_to_offset_safe(entry["rva"])
            if off is None:
                continue
            size = min(entry["size"], len(self.data) - off)
            blob = self.data[off:off + size]
            try:
                return _parse_version_info(blob)
            except Exception as exc:  # pragma: no cover - defensive
                self.warnings.append(f"version resource at {path} unparsable: {exc}")
        return {}

    # -- debug / pdb -------------------------------------------------------- #

    def debug_entries(self) -> list[dict[str, Any]]:
        rva, size = self.dir(6)
        if not rva:
            return []
        base = self.rva_to_offset_safe(rva)
        if base is None:
            return []
        out: list[dict[str, Any]] = []
        count = min(size // 28, 64)
        for i in range(count):
            off = base + i * 28
            if off + 28 > len(self.data):
                break
            (_ch, ts, maj, mino, typ, dsize, addr_raw, ptr_raw) = struct.unpack_from(
                "<IIHHIIII", self.data, off)
            entry = {"type": typ, "timestamp": ts, "size": dsize}
            if typ == 2 and ptr_raw and ptr_raw + dsize <= len(self.data):
                blob = self.data[ptr_raw:ptr_raw + dsize]
                if blob[:4] in (b"RSDS", b"NB10") and len(blob) > 24:
                    if blob[:4] == b"RSDS":
                        guid = _guid_from_bytes(blob[4:20])
                        age = struct.unpack_from("<I", blob, 20)[0]
                        entry["guid"] = guid
                        entry["age"] = age
                        entry["pdb"] = _cstring(blob, 24, 512)
                    else:
                        offset = struct.unpack_from("<I", blob, 8)[0]
                        entry["pdb"] = _cstring(blob, 16, 512)
                        entry["age"] = offset
            out.append(entry)
        return out

    # -- rich header -------------------------------------------------------- #

    def rich_header(self) -> dict[str, Any]:
        data = self.data
        end = min(self.pe_offset, len(data))
        idx = data.rfind(b"Rich", 0x40, end)
        if idx < 0 or idx + 8 > len(data):
            return {}
        key = _u32(data, idx + 4)
        # Decode backwards looking for the "DanS" start marker.
        start = None
        pos = idx - 4
        while pos >= 0x40:
            if struct.unpack_from("<I", data, pos)[0] ^ key == 0x536E6144:  # 'DanS'
                start = pos
                break
            pos -= 4
        if start is None:
            return {"present": True, "key": key, "entries": []}
        entries: dict[int, int] = {}
        p = start + 16
        while p + 8 <= idx:
            comp_id = _u32(data, p) ^ key
            count = _u32(data, p + 4) ^ key
            entries[comp_id] = entries.get(comp_id, 0) + count
            p += 8
        builds = sorted(((cid >> 16, cnt) for cid, cnt in entries.items()), reverse=True)
        return {
            "present": True,
            "key": key,
            "entries": len(entries),
            "builds": builds[:8],
        }

    # -- .NET --------------------------------------------------------------- #

    def dotnet(self) -> dict[str, Any] | None:
        rva, size = self.dir(14)
        if not rva or not size:
            return None
        off = self.rva_to_offset_safe(rva)
        if off is None or off + 72 > len(self.data):
            return {"present": True, "error": "CLR header unmapped"}
        (_cb, major, minor, md_rva, md_size, flags, entry_token) = struct.unpack_from(
            "<IHHIIII", self.data, off)
        info: dict[str, Any] = {
            "present": True,
            "runtime": f"v{major}.{minor}",
            "header_version": f"{major}.{minor}",
            "flags": flag_names(flags, COMIMAGE_FLAGS),
            "flags_raw": flags,
            "entry_token": f"0x{entry_token:08x}",
            "metadata_size": md_size,
        }
        md_off = self.rva_to_offset_safe(md_rva)
        if md_off is not None and md_off + 16 <= len(self.data):
            md = self.data
            if md[md_off:md_off + 4] == b"BSJB":
                ver_len = _u32(md, md_off + 12)
                ver_len = min(ver_len, 255)
                raw = md[md_off + 16: md_off + 16 + ver_len]
                version = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
                info["metadata_version"] = version
                if version:
                    info["runtime"] = version
        return info

    # -- overlay / certificate table ---------------------------------------- #

    def sections_raw_end(self) -> int:
        end = self.size_of_headers if self.size_of_headers else 0
        for sec in self.sections:
            if sec.raw_size:
                end = max(end, sec.raw_ptr + sec.raw_size)
        return min(end, len(self.data))

    def overlay(self) -> tuple[int, int]:
        start = self.sections_raw_end()
        return start, max(0, len(self.data) - start)

    def certificate_table(self) -> tuple[int, int]:
        """(file offset, size) of the Authenticode table; (0, 0) when absent."""
        off, size = self.dir(4)
        if not off or not size:
            return (0, 0)
        if off >= len(self.data):
            return (0, 0)
        return (off, min(size, len(self.data) - off))

    # -- objects stored in data directories we only report ------------------ #

    def security_directory_raw(self) -> tuple[int, int]:
        return self.dir(4)


# --------------------------------------------------------------------------- #
# VS_VERSIONINFO
# --------------------------------------------------------------------------- #

def _utf16z(buf: bytes, off: int, end: int) -> str:
    """Read a UTF-16LE NUL-terminated string inside [off, end)."""
    p = off
    while p + 1 < end:
        if buf[p] == 0 and buf[p + 1] == 0:
            return buf[off:p].decode("utf-16-le", "replace")
        p += 2
    return buf[off:end].decode("utf-16-le", "replace")


def _align4(n: int) -> int:
    return (n + 3) & ~3


def _parse_version_info(blob: bytes) -> dict[str, Any]:
    """Parse a VS_VERSIONINFO resource blob into a flat dict."""
    result: dict[str, Any] = {"strings": {}, "fixed": {}}

    def walk(off: int, end: int, depth: int) -> None:
        if depth > 4 or off + 6 > end:
            return
        w_len = _u16(blob, off)
        w_val = _u16(blob, off + 2)
        # w_type = _u16(blob, off + 4)
        if w_len < 6:
            return
        block_end = min(off + w_len, end)
        key = _utf16z(blob, off + 6, block_end)
        key_after = off + 6 + (len(key) + 1) * 2
        val_off = _align4(key_after)

        if key == "VS_VERSION_INFO" and w_val >= 52:
            if val_off + 52 <= len(blob):
                sig, struc, fv_ms, fv_ls, pv_ms, pv_ls = struct.unpack_from(
                    "<IIIIII", blob, val_off)
                result["fixed"] = {
                    "signature": f"0x{sig:08x}",
                    "file_version": _quad4(fv_ms, fv_ls),
                    "product_version": _quad4(pv_ms, pv_ls),
                }
            child = _align4(val_off + w_val) if w_val else _align4(key_after)
            while child + 6 <= block_end:
                walk(child, block_end, depth + 1)
                step = _u16(blob, child)
                if step < 6:
                    break
                child = _align4(child + step)
            return

        if key in ("StringFileInfo", "VarFileInfo") or depth == 2:
            child = _align4(key_after) + w_val if w_val else _align4(key_after)
            child = _align4(child)
            while child + 6 <= block_end:
                walk(child, block_end, depth + 1)
                step = _u16(blob, child)
                if step < 6:
                    break
                child = _align4(child + step)
            return

        if w_val:
            if w_val == 1 and key in ("Translation",):
                pass
            raw = blob[val_off: val_off + w_val * 2]
            try:
                text = raw.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                text = ""
            result["strings"][key] = text

    walk(0, len(blob), 0)
    return result


def _quad4(ms: int, ls: int) -> str:
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _guid_from_bytes(raw: bytes) -> str:
    if len(raw) < 16:
        return ""
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    rest = raw[8:16]
    return (
        f"{d1:08X}-{d2:04X}-{d3:04X}-"
        f"{rest[0]:02X}{rest[1]:02X}-{''.join(f'{b:02X}' for b in rest[2:])}"
    )
