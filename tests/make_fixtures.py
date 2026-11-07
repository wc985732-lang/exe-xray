"""Build small synthetic PE files used by the test suite.

These are hand-assembled PE32 images: no compiler involved, no execution
anywhere. They exist so the parser, the capability table, the packer heuristics
and the CLI can be exercised deterministically on any machine.
"""

from __future__ import annotations

import math
import os
import random
import struct

IMAGE_FILE_MACHINE_I386 = 0x014C
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _checksum(data: bytearray, checksum_offset: int) -> int:
    total = 0
    n = len(data)
    i = 0
    while i + 1 < n:
        if i == checksum_offset:
            i += 4
            continue
        total += data[i] | (data[i + 1] << 8)
        if total > 0xFFFFFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if i < n:
        total += data[i]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + n) & 0xFFFFFFFF


def _build_import_blob(dlls: dict[str, list[str]], section_rva: int) -> tuple[bytes, int]:
    """Return (section blob, size of the descriptor table)."""
    names = list(dlls.items())
    desc_size = (len(names) + 1) * 20

    pos = desc_size
    int_rvas: list[int] = []
    for _name, funcs in names:
        int_rvas.append(pos)
        pos += (len(funcs) + 1) * 4
    iat_rvas: list[int] = []
    for _name, funcs in names:
        iat_rvas.append(pos)
        pos += (len(funcs) + 1) * 4

    hint_rvas: list[list[int]] = []
    for _name, funcs in names:
        entries = []
        for fn in funcs:
            entries.append(pos)
            pos += 2 + len(fn) + 1
            pos = _align(pos, 2)
        hint_rvas.append(entries)

    dll_rvas: list[int] = []
    for name, _funcs in names:
        dll_rvas.append(pos)
        pos += len(name) + 1
        pos = _align(pos, 2)

    buf = bytearray(pos)

    def put32(offset: int, value: int) -> None:
        struct.pack_into("<I", buf, offset, value)

    def putstr(offset: int, text: str) -> None:
        buf[offset:offset + len(text)] = text.encode("ascii")
        buf[offset + len(text)] = 0

    for i, (_name, funcs) in enumerate(names):
        base = i * 20
        put32(base + 0, section_rva + int_rvas[i])
        put32(base + 4, 0)
        put32(base + 8, 0)
        put32(base + 12, section_rva + dll_rvas[i])
        put32(base + 16, section_rva + iat_rvas[i])
        for j in range(len(funcs)):
            put32(int_rvas[i] + j * 4, section_rva + hint_rvas[i][j])
            put32(iat_rvas[i] + j * 4, section_rva + hint_rvas[i][j])
        putstr(dll_rvas[i], _name)
    # hint/name entries (2-byte hint then name)
    for i, (_name, funcs) in enumerate(names):
        for j, fn in enumerate(funcs):
            off = hint_rvas[i][j]
            struct.pack_into("<H", buf, off, 0)
            putstr(off + 2, fn)
    return bytes(buf), desc_size


def build_pe(
    *,
    subsystem: int = 3,
    dll_characteristics: int = 0,
    sections: list[tuple] | None = None,
    imports: dict[str, list[str]] | None = None,
    extra_data: bytes = b"",
    entry_section: int = 0,
    clr_section: int | None = None,
) -> bytes:
    """Assemble a PE32 image.

    ``sections`` is a list of ``(name, payload, characteristics)`` records. A
    fourth element overrides the declared virtual size, and ``payload=None``
    means the section stores no bytes at all (raw size 0) while still occupying
    memory - that is what an unpack destination looks like, and what the Windows
    linker's zero-filled ``Pad`` sections look like.

    The first section holds the import table when ``imports`` is given, so its
    RVA must stay 0x1000 - we always place the import blob in section 0.

    ``entry_section`` moves ``AddressOfEntryPoint`` into another section, and
    ``clr_section`` points ``IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`` at a section
    that holds a CLR header, so a fixture can declare itself a managed image.

    Section RVAs are laid out after each other (aligned to ``SECTION_ALIGNMENT``),
    the way a linker does it, so a section can be larger than one page without
    colliding with its neighbour.
    """
    imports = imports or {}
    if sections is None:
        sections = [("", b"", 0x60000020)]

    if imports:
        import_blob, import_size = _build_import_blob(imports, SECTION_ALIGNMENT)
        head = list(sections[0]) if sections else ["", b"", 0x60000020]
        head[1] = import_blob + extra_data
        sections = [tuple(head)] + list(sections[1:])
        # keep the string fixtures somewhere findable as well
    elif extra_data and sections:
        head = list(sections[0])
        head[1] = (head[1] or b"") + extra_data
        sections[0] = tuple(head)
    else:
        import_size = 0

    nsect = len(sections)
    size_of_headers = 0x400

    # virtual size and RVA of every section, in declaration order
    virtual_sizes: list[int] = []
    rvas: list[int] = []
    cursor = SECTION_ALIGNMENT
    for entry in sections:
        payload = entry[1]
        override = entry[3] if len(entry) > 3 else None
        if payload is None:
            virtual_size = override or 0
        else:
            virtual_size = override if override is not None else len(payload)
        virtual_sizes.append(virtual_size)
        rvas.append(cursor)
        cursor = _align(cursor + max(virtual_size, 1), SECTION_ALIGNMENT)
    size_of_image = cursor

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", IMAGE_FILE_MACHINE_I386, nsect, 0x5F000000,
                       0, 0, 0xE0, 0x0102)

    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    opt[2] = 14
    opt[3] = 0
    struct.pack_into("<I", opt, 4, 0x200)      # SizeOfCode
    struct.pack_into("<I", opt, 8, 0x200)      # SizeOfInitializedData
    struct.pack_into("<I", opt, 16, rvas[entry_section])  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, rvas[entry_section])  # BaseOfCode
    struct.pack_into("<I", opt, 24, SECTION_ALIGNMENT * 2)  # BaseOfData
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", opt, 36, FILE_ALIGNMENT)
    struct.pack_into("<HH", opt, 40, 6, 0)
    struct.pack_into("<HH", opt, 44, 0, 0)
    struct.pack_into("<HH", opt, 48, 6, 0)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, size_of_headers)
    struct.pack_into("<H", opt, 68, subsystem)
    struct.pack_into("<H", opt, 70, dll_characteristics)
    struct.pack_into("<I", opt, 72, 0x100000)
    struct.pack_into("<I", opt, 76, 0x1000)
    struct.pack_into("<I", opt, 80, 0x100000)
    struct.pack_into("<I", opt, 84, 0x1000)
    struct.pack_into("<I", opt, 92, 16)
    if imports:
        struct.pack_into("<II", opt, 96 + 8, SECTION_ALIGNMENT, import_size)
    if clr_section is not None:
        struct.pack_into("<II", opt, 96 + 14 * 8, rvas[clr_section],
                         virtual_sizes[clr_section])

    sec_headers = bytearray()
    body = bytearray()
    raw_cursor = size_of_headers

    for index, entry in enumerate(sections):
        name, payload, chars = entry[0], entry[1], entry[2]
        rva = rvas[index]
        virtual_size = virtual_sizes[index]
        if payload is None:
            stored = b""
            raw_size = 0
        else:
            stored = payload
            raw_size = max(FILE_ALIGNMENT, _align(len(stored), FILE_ALIGNMENT))
            stored = stored + b"\x00" * (raw_size - len(stored))
        sec_headers += struct.pack("<8sIIIIIIHHI", name.encode("latin-1")[:8].ljust(8, b"\x00"),
                                   virtual_size, rva, raw_size, raw_cursor,
                                   0, 0, 0, 0, chars)
        body += stored
        raw_cursor += raw_size

    header = bytearray(dos)
    header += b"PE\x00\x00" + coff + bytes(opt) + bytes(sec_headers)
    image = bytearray(header)
    image += b"\x00" * (size_of_headers - len(image))
    image += body
    struct.pack_into("<I", image, 0x40 + 24 + 64, _checksum(image, 0x40 + 24 + 64))
    return bytes(image)


def high_entropy_blob(size: int, seed: int = 1) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


# --------------------------------------------------------------------------- #
# the three fixtures
# --------------------------------------------------------------------------- #

def clean_exe() -> bytes:
    return build_pe(
        subsystem=3,
        dll_characteristics=0x0140,
        imports={"KERNEL32.dll": ["ExitProcess", "GetCommandLineW", "Sleep"]},
        sections=[(".text", b"\x55\x8b\xec\x33\xc0\x5d\xc3" * 20, 0x60000020),
                  (".data", b"hello\0world\0", 0xC0000040)],
    )


def packed_exe() -> bytes:
    stub = b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed" + b"\x90" * 120
    return build_pe(
        subsystem=2,
        imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress"]},
        sections=[("UPX0", b"\x00" * 0x2000, 0xE0000080),
                  ("UPX1", stub + high_entropy_blob(0x1800, seed=7), 0xE0000020)],
    )


def suspicious_exe() -> bytes:
    strings = (
        b"http://c2.example.invalid/gate.php?id=%s\0"
        b"https://discord.com/api/webhooks/1234567890/abcdefg\0"
        b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
        b"C:\\Users\\Public\\svchost32.exe\0"
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\0"
        b"password=\0"
        b"cmd.exe /c schtasks /create /sc minute /mo 5 /tn Updater\0"
    )
    return build_pe(
        subsystem=2,
        imports={
            "WS2_32.dll": ["WSAStartup", "socket", "connect", "send", "recv", "closesocket"],
            "USER32.dll": ["GetAsyncKeyState", "SetWindowsHookExA", "GetForegroundWindow"],
            "KERNEL32.dll": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                             "OpenProcess", "CreateProcessW", "IsDebuggerPresent"],
            "ADVAPI32.dll": ["RegSetValueExW", "CreateServiceW", "OpenSCManagerA"],
        },
        sections=[(".text", b"\x55\x8b\xec" * 400, 0x60000020),
                  (".data", strings, 0xC0000040)],
    )


# --------------------------------------------------------------------------- #
# packing fixtures
# --------------------------------------------------------------------------- #
#
# Each one isolates exactly one observable, so a test can say which rule fired.
# They are built to the *shapes measured on real images* (see NOTES-packing.md):
# UPX's two-section layout, the Windows linker's zero-filled Pad sections, a
# managed assembly's one import, and the compressed-resource pattern.

CODE_X_R = 0x60000020            # CNT_CODE | MEM_EXECUTE | MEM_READ
DATA_R = 0x40000040              # CNT_INITIALIZED_DATA | MEM_READ
DATA_RW = 0xC0000040             # ... plus MEM_WRITE
CODE_RWX = 0xE0000020            # CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE
PAD_X_R_DISCARD = 0x62000040     # MEM_EXECUTE | MEM_READ | MEM_DISCARDABLE

CLR_HEADER_SIZE = 72


def _clr_header(entry_token: int = 0x06000001, flags: int = 1) -> bytes:
    """A minimal IMAGE_COR20_HEADER: managed flags and an entry token."""
    blob = bytearray(CLR_HEADER_SIZE)
    struct.pack_into("<IHHIIII", blob, 0,
                     CLR_HEADER_SIZE, 2, 5,      # cb, runtime major/minor
                     0, 0,                       # MetaData rva/size
                     flags, entry_token)
    return bytes(blob)


def stub_without_packer_names() -> bytes:
    """A compressor's layout with every packer name removed.

    ``.stub`` holds a resolver-only import table, ``.dst`` is executable memory
    with no bytes on disk, and ``.blob`` is the compressed body - which is also
    where execution starts. No section name points at any packer, so only
    structural evidence can catch this one.
    """
    return build_pe(
        subsystem=2,
        imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"]},
        sections=[(".stub", b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed" + b"\x90" * 64, CODE_X_R),
                  (".blob", high_entropy_blob(0x12000, seed=23), CODE_X_R),
                  (".dst", None, CODE_RWX, 0x20000)],
        entry_section=1,
    )


def linker_pad_sections() -> bytes:
    """The shape that used to be called packed: ``ntoskrnl.exe``/``hvax64.exe``.

    A zero-filled section that is executable but read-only and discardable, one
    import, entry point outside the first section. Every signal here is weak and
    none of them is structural, so it must not be reported as packed.
    """
    return build_pe(
        subsystem=3,
        imports={"KDSTUB.dll": ["KiSystemStartupThunk"]},
        sections=[(".rdata", b"\x00" * 0x200, DATA_R),
                  (".text", b"\x55\x8b\xec\x33\xc0\x5d\xc3" * 40, CODE_X_R),
                  ("Pad2", None, PAD_X_R_DISCARD, 0x20000)],
        entry_section=1,
    )


def managed_exe(hot_text: bool = True) -> bytes:
    """A managed EXE the way csc emits one: one import, high-entropy IL.

    ``mscoree.dll!_CorExeMain`` is the only import a framework EXE has, and IL
    metadata heaps are close to random, so both numbers are the CLR convention
    rather than packer evidence.
    """
    body = high_entropy_blob(0x6000, seed=31) if hot_text else b"\x72\x01\x00\x00\x70" * 800
    return build_pe(
        subsystem=3,
        imports={"mscoree.dll": ["_CorExeMain"]},
        # a real .text carries the native jump stub, the imports, the IL and the
        # metadata in one section, and the entry point sits in it
        sections=[(".text", b"", CODE_X_R),
                  ("clr", _clr_header(), DATA_R)],
        extra_data=body,
        entry_section=0,
        clr_section=1,
    )


def managed_exe_without_imports() -> bytes:
    """A managed EXE with an empty import table and otherwise clean headers.

    ``C:\\Windows\\System32\\tzsync.exe`` looks exactly like this: a CLR header,
    no import directory at all, ordinary section names. A CLR host can start such
    an image, so an empty import table alone is not packer evidence.
    """
    return build_pe(
        subsystem=3,
        imports={},
        sections=[(".text", high_entropy_blob(0x6000, seed=43), CODE_X_R),
                  ("clr", _clr_header(), DATA_R)],
        clr_section=1,
    )


def managed_protected_exe() -> bytes:
    """A managed EXE whose headers no toolchain would emit.

    An empty import table plus a section whose name contains a control byte: the
    header was rewritten by a protector.
    """
    return build_pe(
        subsystem=2,
        imports={},
        sections=[("7~I((CD\x1e", b"\x90" * 0x400, CODE_RWX),
                  (".text", high_entropy_blob(0x6000, seed=37), CODE_X_R),
                  ("clr", _clr_header(), DATA_R)],
        clr_section=2,
    )


def resource_only_image() -> bytes:
    """Strings and manifests, no code and no imports: much of System32.

    Seventy-one stock Windows DLLs are shaped like this (``msobjs.dll``,
    ``nlsbres.dll``, the ``Windows.UI.Xaml.Resources.*`` family): no executable
    section, no import table, nothing to call.
    """
    return build_pe(
        subsystem=2,
        imports={},
        sections=[(".rsrc", b"<assembly manifest/>" * 2000, DATA_R),
                  (".data", high_entropy_blob(0x4000, seed=47), DATA_RW)],
    )


def compressed_resource_only() -> bytes:
    """Ordinary code plus a compressed resource: high entropy, no packing.

    Installers legitimately carry compressed icons and payloads in ``.rsrc``;
    that section is not executable, so its entropy says nothing about the code.
    """
    return build_pe(
        subsystem=2,
        imports={"KERNEL32.dll": ["ExitProcess", "GetCommandLineW", "Sleep",
                                  "CreateFileW", "ReadFile", "WriteFile",
                                  "CloseHandle", "GetLastError", "SetLastError",
                                  "HeapAlloc", "HeapFree", "GetProcessHeap",
                                  "VirtualAlloc", "VirtualFree"]},
        sections=[(".text", b"\x55\x8b\xec\x33\xc0\x5d\xc3" * 200, CODE_X_R),
                  (".rsrc", high_entropy_blob(0x8000, seed=41), DATA_R)],
    )


def upx_named_only() -> bytes:
    """Two sections named after one packer, and nothing else.

    The name evidence is one observation seen twice, so the score must be the
    single identity credit, not two of them added together.
    """
    return build_pe(
        subsystem=2,
        imports={"KERNEL32.dll": [f"Api{i:02d}" for i in range(20)]},
        sections=[("UPX0", b"\x90" * 0x400, CODE_X_R),
                  ("UPX1", b"\xcc" * 0x400, CODE_X_R)],
    )


def corroboration_only() -> bytes:
    """Three weak signals and no structural one.

    Few imports, a hot code section and an entry point outside section 0 add up
    past the suspect line, but nothing here requires a stub: this is the shape of
    an odd-but-legitimate image (``d3dcsx_42.dll`` with a moved entry point), so
    the score must be held below the verdict band.
    """
    return build_pe(
        subsystem=3,
        imports={"KERNEL32.dll": ["D3DCompileFromFile"]},
        sections=[(".rdata", b"\x00" * 0x200, DATA_R),
                  (".text", high_entropy_blob(0x12000, seed=53), CODE_X_R)],
        entry_section=1,
    )


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "fixtures")
    os.makedirs(out, exist_ok=True)
    for name, blob in (("clean.exe", clean_exe()),
                       ("packed.exe", packed_exe()),
                       ("suspicious.exe", suspicious_exe())):
        path = os.path.join(out, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        print(f"{path}  {len(blob)} bytes")


if __name__ == "__main__":
    main()
