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
    sections: list[tuple[str, bytes, int]] | None = None,
    imports: dict[str, list[str]] | None = None,
    extra_data: bytes = b"",
) -> bytes:
    """Assemble a PE32 image.

    ``sections`` is a list of (name, payload, characteristics). The first
    section holds the import table when ``imports`` is given, so its RVA must
    stay 0x1000 - we always place the import blob in section 0.
    """
    imports = imports or {}
    if sections is None:
        sections = [("", b"", 0x60000020)]

    if imports:
        import_blob, import_size = _build_import_blob(imports, SECTION_ALIGNMENT)
        head_name = sections[0][0] if sections else ""
        head_chars = sections[0][2] if sections else 0x60000020
        sections = [(head_name, import_blob + extra_data, head_chars)] + list(sections[1:])
        # keep the string fixtures somewhere findable as well
    elif extra_data and sections:
        name, payload, chars = sections[0]
        sections[0] = (name, payload + extra_data, chars)
    else:
        import_size = 0

    nsect = len(sections)
    size_of_image = SECTION_ALIGNMENT * (nsect + 1)
    size_of_headers = 0x400

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
    struct.pack_into("<I", opt, 16, SECTION_ALIGNMENT)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, SECTION_ALIGNMENT)  # BaseOfCode
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

    sec_headers = bytearray()
    body = bytearray()
    raw_cursor = size_of_headers

    for index, (name, payload, chars) in enumerate(sections):
        rva = SECTION_ALIGNMENT * (index + 1)
        stored = payload
        raw_size = max(FILE_ALIGNMENT, _align(len(stored), FILE_ALIGNMENT))
        stored = stored + b"\x00" * (raw_size - len(stored))
        sec_headers += struct.pack("<8sIIIIIIHHI", name.encode("ascii")[:8].ljust(8, b"\x00"),
                                   len(payload), rva, raw_size, raw_cursor,
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
