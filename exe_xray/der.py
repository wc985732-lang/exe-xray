"""A very small ASN.1 (DER/BER) reader.

Only what Authenticode needs: decoding a PKCS#7 SignedData blob into a tree of
tagged nodes, pulling out OIDs, integers, octet strings and nested structures.
Definite lengths only. No certificates are validated and no crypto is done.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class DERError(ValueError):
    """Malformed or unsupported ASN.1 input."""


CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_BITSTRING = 3
TAG_OCTETSTRING = 4
TAG_NULL = 5
TAG_OID = 6
TAG_SEQUENCE = 16
TAG_SET = 17


@dataclass
class Node:
    cls: int
    constructed: bool
    number: int
    value: bytes = b""
    children: list["Node"] = field(default_factory=list)
    start: int = 0
    end: int = 0

    # -- predicates ------------------------------------------------------- #

    @property
    def is_universal(self) -> bool:
        return self.cls == CLASS_UNIVERSAL

    @property
    def is_sequence(self) -> bool:
        return self.is_universal and self.number == TAG_SEQUENCE

    @property
    def is_set(self) -> bool:
        return self.is_universal and self.number == TAG_SET

    def at(self, index: int) -> "Node | None":
        if 0 <= index < len(self.children):
            return self.children[index]
        return None

    def oid(self) -> str | None:
        if not (self.is_universal and self.number == TAG_OID):
            return None
        return decode_oid(self.value)

    def integer(self) -> int | None:
        if not (self.is_universal and self.number == TAG_INTEGER) or not self.value:
            return None
        return int.from_bytes(self.value, "big", signed=True)

    def text(self) -> str | None:
        if self.is_universal and self.number in (12, 19, 20, 22, 30, 28):  # UTF8/Printable/etc
            try:
                return self.value.decode("utf-8", "replace")
            except Exception:
                return None
        return None

    def find_context(self, number: int) -> "Node | None":
        for child in self.children:
            if child.cls == CLASS_CONTEXT and child.number == number:
                return child
        return None

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def _read_tag(buf: bytes, off: int) -> tuple[int, bool, int, int]:
    if off >= len(buf):
        raise DERError("unexpected end of input while reading tag")
    b = buf[off]
    cls = b >> 6
    constructed = bool(b & 0x20)
    number = b & 0x1F
    off += 1
    if number == 0x1F:  # high tag number form
        number = 0
        while True:
            if off >= len(buf):
                raise DERError("truncated high-tag-number")
            c = buf[off]
            off += 1
            number = (number << 7) | (c & 0x7F)
            if not c & 0x80:
                break
            if number > 0xFFFFFF:
                raise DERError("tag number too large")
    return cls, constructed, number, off


def _read_length(buf: bytes, off: int) -> tuple[int, int]:
    if off >= len(buf):
        raise DERError("unexpected end of input while reading length")
    b = buf[off]
    off += 1
    if b == 0x80:
        raise DERError("indefinite length is not supported")
    if b < 0x80:
        return b, off
    count = b & 0x7F
    if count > 4:
        raise DERError(f"length field too long ({count} bytes)")
    if off + count > len(buf):
        raise DERError("truncated long-form length")
    value = int.from_bytes(buf[off:off + count], "big")
    return value, off + count


def parse_node(buf: bytes, off: int, end: int | None = None) -> tuple[Node, int]:
    if end is None:
        end = len(buf)
    start = off
    cls, constructed, number, off = _read_tag(buf, off)
    length, off = _read_length(buf, off)
    value_end = off + length
    if value_end > end or value_end > len(buf):
        raise DERError(
            f"node at 0x{start:x} claims {length} content bytes, truncated by container")
    node = Node(cls, constructed, number, start=start, end=value_end)
    if constructed:
        p = off
        guard = 0
        while p < value_end:
            child, p = parse_node(buf, p, value_end)
            node.children.append(child)
            guard += 1
            if guard > 100000:
                raise DERError("too many nested nodes")
        if p != value_end:
            raise DERError(f"constructed node at 0x{start:x} overruns its length")
    else:
        node.value = buf[off:value_end]
    return node, value_end


def decode(buf: bytes, off: int = 0) -> Node:
    node, _ = parse_node(buf, off)
    return node


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)
