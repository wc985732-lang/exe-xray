"""Authenticode: verify the embedded PKCS#7 signature.

What this module actually proves, end to end:

1. ``SpcIndirectDataContent.messageDigest`` equals a fresh hash of the image,
   computed the way oleaut32 does it (headers minus the checksum and the
   security directory, then every section, then the overlay).
2. The ``messageDigest`` *signed attribute* equals the hash of those
   SpcIndirectDataContent bytes. That attribute lives inside the SignedAttributes
   set, which is what the signature covers, so it cannot be rewritten without
   the signer's private key. This is the step that makes a forged nominal digest
   useless: an attacker who flips a byte and patches step 1 still fails here.
3. The ``encryptedDigest`` is a valid RSA PKCS#1 v1.5 signature over the DER
   encoding of those SignedAttributes (re-tagged as a SET OF, per CMS) using the
   public key inside the certificate named by issuerAndSerialNumber.

What it does not prove: that the certificate chains to a trusted root, that it
is unrevoked, or that a timestamp is authoritative. Those need the Windows trust
store (WinVerifyTrust) and stay out of scope, which is why ``chain_verified``
remains False even for a ``valid`` result.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from .der import DERError, Node, decode
from .pe import PE

DIGEST_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
}

SIGNING_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.10045.2.1": "ECDSA",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA512",
}

OID_SPC_INDIRECT = "1.3.6.1.4.1.311.2.1.4"
OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_COUNTERSIGNATURE = "1.2.840.113549.1.9.6"
OID_RFC3161_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"

# PKCS#1 v1.5 block type 1 requires at least 8 bytes of 0xFF padding.
MIN_PS_LEN = 8

NAME_OIDS = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}


# --------------------------------------------------------------------------- #
# file digest covered by the signature
# --------------------------------------------------------------------------- #

def authenticode_digest(pe: PE, algo: str) -> bytes:
    """Hash the file the way oleaut32 does before verifying a signature."""
    data = pe.data
    hasher = hashlib.new(algo)

    checksum_off = pe.checksum_offset
    sec_dir_off = pe.data_directory_offset + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY
    size_of_headers = min(pe.size_of_headers or 0, len(data))

    cursor = 0  # last file offset already hashed

    # 1) everything before the checksum field
    end = min(checksum_off, len(data))
    hasher.update(data[:end])
    cursor = end

    # 2) skip the 4-byte checksum, then up to the security directory entry
    start = min(checksum_off + 4, len(data))
    end = min(sec_dir_off, len(data))
    if end > start:
        hasher.update(data[start:end])
        cursor = end

    # 3) skip the 8-byte security directory entry, then the rest of the headers
    start = min(sec_dir_off + 8, len(data))
    end = max(min(size_of_headers, len(data)), start)
    if end > start:
        hasher.update(data[start:end])
        cursor = end

    # 4) every section's raw data, in file order
    for sec in sorted(pe.sections, key=lambda s: s.raw_ptr):
        if not sec.raw_size:
            continue
        s = sec.raw_ptr
        e = min(s + sec.raw_size, len(data))
        if e <= s:
            continue
        hasher.update(data[s:e])
        cursor = max(cursor, e)

    # 5) trailing data (overlay) up to the certificate table itself
    cert_off, cert_size = pe.certificate_table()
    if cert_off and cert_off > cursor:
        hasher.update(data[cursor:cert_off])
    return hasher.digest()


# --------------------------------------------------------------------------- #
# small DER helpers
# --------------------------------------------------------------------------- #

def _der_content(buf: bytes, node: Node) -> bytes:
    """The content octets of one TLV, whatever length form its header used."""
    off = node.start
    try:
        first = buf[off]
        off += 1
        if first & 0x1F == 0x1F:  # high-tag-number form
            while buf[off] & 0x80:
                off += 1
            off += 1
        length = buf[off]
        off += 1
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4:
                return b""
            off += count
        if off > node.end:
            return b""
        return buf[off:node.end]
    except IndexError:
        return b""


def _time_to_iso(node: Node | None) -> str:
    if node is None:
        return ""
    raw = node.value.decode("ascii", "replace").strip()
    try:
        if raw.endswith("Z"):
            body = raw[:-1]
            if len(body) == 12:  # UTCTime YYMMDDhhmmss
                yy = int(body[0:2])
                year = 2000 + yy if yy < 50 else 1900 + yy
                body = f"{year:04d}" + body[2:]
            if len(body) >= 14:
                return (f"{body[0:4]}-{body[4:6]}-{body[6:8]} "
                        f"{body[8:10]}:{body[10:12]}:{body[12:14]}Z")
    except Exception:
        pass
    return raw


def _dn(node: Node | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if node is None or not node.is_sequence:
        return out
    for rdn_set in node.children:
        for attr in rdn_set.children:
            if not attr.is_sequence:
                continue
            oid_node = attr.children[0] if attr.children else None
            val_node = attr.children[1] if len(attr.children) > 1 else None
            if oid_node is None or val_node is None:
                continue
            oid = oid_node.oid() or ""
            label = NAME_OIDS.get(oid, oid)
            text = val_node.text() or ""
            if text and label not in out:
                out[label] = text
    return out


def _format_dn(parts: dict[str, str]) -> str:
    order = ["CN", "OU", "O", "L", "ST", "C"]
    chunks = [f"{k}={parts[k]}" for k in order if parts.get(k)]
    if not chunks:
        chunks = [f"{k}={v}" for k, v in parts.items()]
    return ", ".join(chunks)


# --------------------------------------------------------------------------- #
# certificates and public keys
# --------------------------------------------------------------------------- #

def _parse_public_key(spki: Node | None) -> dict[str, Any]:
    """Pull (n, e) out of a SubjectPublicKeyInfo, or describe why we cannot."""
    if spki is None or not spki.is_sequence or len(spki.children) < 2:
        return {"kind": "missing"}
    alg = spki.children[0]
    bits = spki.children[1]
    key_oid = _oid_of(alg.children[0]) if alg.children else ""
    if not (bits.is_universal and bits.number == 3) or not bits.value:
        return {"kind": "unsupported", "key_oid": key_oid,
                "reason": "SubjectPublicKeyInfo holds no BIT STRING key"}
    raw = bits.value[1:]  # drop the unused-bits count octet (always 0 here)
    if key_oid == OID_RSA_ENCRYPTION:
        try:
            seq = decode(raw)
            modulus = seq.children[0].integer()
            exponent = seq.children[1].integer()
        except (DERError, IndexError, ValueError):
            return {"kind": "unsupported", "key_oid": key_oid,
                    "reason": "RSAPublicKey could not be decoded"}
        if not modulus or not exponent:
            return {"kind": "unsupported", "key_oid": key_oid,
                    "reason": "RSAPublicKey has an empty modulus or exponent"}
        return {"kind": "rsa", "key_oid": key_oid, "n": modulus, "e": exponent,
                "bits": modulus.bit_length()}
    if key_oid == OID_EC_PUBLIC_KEY:
        curve = _oid_of(alg.children[1]) if len(alg.children) > 1 else ""
        return {"kind": "ecdsa", "key_oid": key_oid, "curve": curve,
                "reason": "ECDSA signature verification is not implemented here"}
    return {"kind": "unsupported", "key_oid": key_oid,
            "reason": f"public key algorithm {key_oid or 'unknown'} is not RSA"}


def _parse_certificate(seq: Node, buf: bytes) -> dict[str, Any] | None:
    if not seq.children or not seq.children[0].is_sequence:
        return None
    tbs = seq.children[0]
    kids = tbs.children
    idx = 0
    if kids and kids[0].cls == 2 and kids[0].number == 0:  # [0] version
        idx = 1
    try:
        serial_node = kids[idx]
        issuer = kids[idx + 2]
        validity = kids[idx + 3]
        subject = kids[idx + 4]
    except IndexError:
        return None
    spki = kids[idx + 5] if len(kids) > idx + 5 else None
    not_before = _time_to_iso(validity.children[0]) if len(validity.children) > 0 else ""
    not_after = _time_to_iso(validity.children[1]) if len(validity.children) > 1 else ""
    subj = _dn(subject)
    iss = _dn(issuer)
    serial = serial_node.integer()
    return {
        "subject": _format_dn(subj),
        "subject_parts": subj,
        "issuer": _format_dn(iss),
        "issuer_parts": iss,
        "serial": f"{serial:X}" if serial is not None else "",
        "serial_int": serial,
        "not_before": not_before,
        "not_after": not_after,
        "is_ca": subj == iss,
        "_issuer_der": buf[issuer.start:issuer.end],
        "_subject_der": buf[subject.start:subject.end],
        "_spki": _parse_public_key(spki),
        "_der": buf[seq.start:seq.end],
    }


def _oid_of(node: Node | None) -> str:
    return node.oid() if node is not None and node.is_universal else ""


# --------------------------------------------------------------------------- #
# RSA PKCS#1 v1.5 verification
# --------------------------------------------------------------------------- #

def _rsa_pkcs1v15_verify(key: dict[str, Any], signature: bytes,
                         signed_bytes: bytes, digest_name: str
                         ) -> tuple[str | None, str, dict[str, Any]]:
    """EMSA-PKCS1-v1_5 with the DigestInfo the signer chose.

    Returns (failure_status, detail, facts). failure_status is None on success.
    """
    facts: dict[str, Any] = {}
    modulus = key["n"]
    exponent = key["e"]
    k = (modulus.bit_length() + 7) // 8
    facts["key_bits"] = modulus.bit_length()

    if len(signature) > k:
        signature = signature[-k:]
    elif len(signature) < k:
        signature = signature.rjust(k, b"\x00")
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= modulus:
        return ("signature-invalid",
                "signature value is not smaller than the RSA modulus", facts)

    em = pow(sig_int, exponent, modulus).to_bytes(k, "big")
    if em[0] != 0x00 or em[1] != 0x01:
        return ("signature-invalid",
                "decrypted signature does not start with the PKCS#1 v1.5 block "
                "header 00 01", facts)
    try:
        separator = em.index(0x00, 2)
    except ValueError:
        return ("signature-invalid",
                "decrypted signature has no 0x00 separator after the padding", facts)
    padding_len = separator - 2
    facts["padding_len"] = padding_len
    if padding_len < MIN_PS_LEN:
        return ("signature-invalid",
                f"PKCS#1 padding is only {padding_len} bytes (needs >= {MIN_PS_LEN})",
                facts)
    if em[2:separator] != b"\xff" * padding_len:
        return ("signature-invalid",
                "PKCS#1 padding is not a run of 0xFF bytes", facts)

    digest_info = em[separator + 1:]
    facts["digest_info_len"] = len(digest_info)
    try:
        di = decode(digest_info)
    except DERError:
        return ("signature-invalid", "DigestInfo inside the signature is not valid DER",
                facts)
    if di.end - di.start != len(digest_info):
        return ("signature-invalid",
                "DigestInfo is followed by unexpected trailing bytes", facts)
    if not di.is_sequence or len(di.children) < 2:
        return ("signature-invalid", "DigestInfo is not a SEQUENCE of two elements",
                facts)
    alg = di.children[0]
    inner_oid = _oid_of(alg.children[0]) if alg.children else ""
    inner_name = DIGEST_OIDS.get(inner_oid, "")
    facts["digest_info_oid"] = inner_oid
    if not inner_name:
        return ("unsupported-algorithm",
                f"signature commits to digest algorithm {inner_oid or 'unknown'}, "
                f"which is not one of SHA-1/224/256/384/512", facts)
    facts["digest_info_algorithm"] = inner_name
    if digest_name and inner_name != digest_name:
        return ("signature-invalid",
                f"DigestInfo names {inner_name} but the SignerInfo digestAlgorithm "
                f"is {digest_name}", facts)
    expected = hashlib.new(inner_name, signed_bytes).digest()
    actual = di.children[1].value
    facts["signed_bytes"] = len(signed_bytes)
    if actual != expected:
        return ("signature-invalid",
                "RSA signature does not match the signed attributes "
                "(the attributes or the signature were altered)", facts)
    return (None, "RSA PKCS#1 v1.5 signature verifies", facts)


# --------------------------------------------------------------------------- #
# PKCS#7 helpers
# --------------------------------------------------------------------------- #

def _parse_signed_data(content_info: Node, buf: bytes, depth: int = 0) -> dict[str, Any] | None:
    """Parse a ContentInfo SEQUENCE carrying signedData."""
    if depth > 3 or not content_info.is_sequence or len(content_info.children) < 2:
        return None
    if _oid_of(content_info.children[0]) != "1.2.840.113549.1.7.2":
        return None
    wrapper = content_info.children[1]
    signed = wrapper.children[0] if wrapper.children else None
    if signed is None or not signed.is_sequence:
        return None

    result: dict[str, Any] = {
        "digest_algorithms": [],
        "certs": [],
        "signers": [],
        "content_digest": b"",
        "content_digest_algo": "",
        "content_der": b"",
        "content_octets": b"",
        "timestamped": False,
        "nested": None,
    }

    certs_node: Node | None = None
    content_info_node: Node | None = None

    for child in signed.children:
        if child.cls == 2 and child.number == 0:
            certs_node = child
        elif child.cls == 2 and child.number == 1:
            continue  # CRLs: nothing useful for us here
        elif child.is_sequence and content_info_node is None:
            content_info_node = child

    # digestAlgorithms is the SET right after the version integer
    digest_algo_set = signed.children[1] if len(signed.children) > 1 else None
    if digest_algo_set is not None and digest_algo_set.is_set:
        for alg in digest_algo_set.children:
            if alg.is_sequence and alg.children:
                oid = _oid_of(alg.children[0])
                result["digest_algorithms"].append(DIGEST_OIDS.get(oid, oid))

    # encapsulated content -> SpcIndirectDataContent
    if content_info_node is not None and len(content_info_node.children) >= 2:
        ctype = _oid_of(content_info_node.children[0])
        if ctype == OID_SPC_INDIRECT:
            explicit = content_info_node.children[1]
            spc = explicit.children[0] if explicit.children else None
            if spc is not None and spc.is_sequence and len(spc.children) >= 2:
                digest_info = spc.children[1]
                if digest_info.is_sequence and len(digest_info.children) >= 2:
                    alg = digest_info.children[0]
                    alg_oid = _oid_of(alg.children[0]) if alg.children else ""
                    result["content_digest_algo"] = DIGEST_OIDS.get(alg_oid, alg_oid)
                    result["content_digest"] = digest_info.children[1].value
                # the exact bytes the signed messageDigest attribute commits to
                result["content_der"] = buf[spc.start:spc.end]
                result["content_octets"] = _der_content(buf, spc)

    # certificates
    if certs_node is not None:
        for child in certs_node.children:
            if child.is_sequence:
                parsed = _parse_certificate(child, buf)
                if parsed:
                    result["certs"].append(parsed)

    # signer infos = last SET in SignedData
    signer_infos = None
    for child in reversed(signed.children):
        if child.is_set:
            signer_infos = child
            break
    if signer_infos is not None:
        for si in signer_infos.children:
            if not si.is_sequence or len(si.children) < 3:
                continue
            signer: dict[str, Any] = {"digest": "", "signing": "", "timestamped": False,
                                      "message_digest": b"", "attrs_der": b"",
                                      "signature": b"", "sig_key_oid": ""}
            ids = si.children[1]
            serial = None
            issuer_der = b""
            if ids.is_sequence and len(ids.children) >= 2:
                issuer_node = ids.children[0]
                issuer_der = buf[issuer_node.start:issuer_node.end]
                serial = ids.children[1].integer()
            signer["serial_int"] = serial
            signer["digest"] = ""
            signer["signing"] = ""
            for ch in si.children[2:]:
                if ch.is_sequence and ch.children:
                    oid = _oid_of(ch.children[0])
                    if oid in SIGNING_OIDS:
                        signer["signing"] = SIGNING_OIDS[oid]
                        signer["sig_key_oid"] = oid
                    elif oid in DIGEST_OIDS:
                        signer["digest"] = DIGEST_OIDS[oid]
                if ch.cls == 2 and ch.number == 0:  # authenticated attributes
                    # Re-tag [0] IMPLICIT -> universal SET OF for the signature.
                    raw = buf[ch.start:ch.end]
                    if raw:
                        signer["attrs_der"] = b"\x31" + raw[1:]
                    for attr in ch.children:
                        if not attr.is_sequence or len(attr.children) < 2:
                            continue
                        if _oid_of(attr.children[0]) != OID_MESSAGE_DIGEST:
                            continue
                        values = attr.children[1]
                        if values.children and values.children[0].is_universal:
                            signer["message_digest"] = values.children[0].value
                if ch.is_universal and ch.number == 4:  # encryptedDigest
                    signer["signature"] = ch.value
                if ch.cls == 2 and ch.number == 1:  # unauth attrs
                    for attr in ch.children:
                        if not attr.is_sequence or not attr.children:
                            continue
                        aoid = _oid_of(attr.children[0])
                        if aoid in (OID_COUNTERSIGNATURE, OID_RFC3161_TIMESTAMP):
                            signer["timestamped"] = True
                            result["timestamped"] = True
                        elif aoid == OID_NESTED_SIGNATURE:
                            try:
                                for val in attr.children[1].children:
                                    nested = _parse_signed_data(val, buf, depth + 1)
                                    if nested:
                                        result["nested"] = nested
                            except Exception:
                                pass
            result["signers"].append(signer)

            # attach the matching certificate
            match = None
            for cert in result["certs"]:
                if cert["serial_int"] == serial and cert["_issuer_der"] == issuer_der:
                    match = cert
                    break
            if match is None:
                # fall back to the leaf: the certificate that is nobody's issuer
                issuers = {c["_issuer_der"] for c in result["certs"]}
                leaves = [c for c in result["certs"] if c["_subject_der"] not in issuers]
                match = leaves[0] if leaves else (result["certs"][-1] if result["certs"] else None)
            signer["cert"] = match
            signer["subject"] = match["subject"] if match else ""
            signer["issuer"] = match["issuer"] if match else ""
            signer["not_before"] = match["not_before"] if match else ""
            signer["not_after"] = match["not_after"] if match else ""

    return result


# --------------------------------------------------------------------------- #
# verification driver
# --------------------------------------------------------------------------- #

def _hash_matches(algorithm: str, blob: bytes, expected: bytes) -> bool:
    if not algorithm or not blob or not expected:
        return False
    try:
        return hashlib.new(algorithm, blob).digest() == expected
    except ValueError:
        return False


def _verify_one_signer(signer: dict[str, Any], content_octets: bytes,
                       content_der: bytes) -> tuple[str | None, str, dict[str, Any]]:
    facts: dict[str, Any] = {}
    digest_name = (signer.get("digest") or "").lower()
    message_digest = signer.get("message_digest") or b""

    if message_digest:
        # step 2: the signed attribute must commit to the content we just hashed.
        scope = ""
        if _hash_matches(digest_name, content_octets, message_digest):
            scope = "content-octets"
        elif _hash_matches(digest_name, content_der, message_digest):
            scope = "content-der"
        if not scope:
            if not digest_name:
                return ("unsupported-algorithm",
                        "SignerInfo declares no digest algorithm we can compute", facts)
            return ("digest-mismatch",
                    "the messageDigest signed attribute does not match the image "
                    "content: the attributes were computed over different bytes "
                    "(or the content was rewritten after signing)", facts)
        facts["message_digest_scope"] = scope

    key = (signer.get("cert") or {}).get("_spki") or {}
    if not key or key.get("kind") in (None, "missing"):
        return ("self-consistent",
                "embedded digest matches the signed attributes, but no usable signer "
                "certificate was found: signer identity NOT verified", facts)

    signed_bytes = signer.get("attrs_der") or content_der
    facts["signed_bytes_scope"] = ("signed-attributes" if signer.get("attrs_der")
                                   else "content-der")
    signature = signer.get("signature") or b""
    if not signature:
        return ("signature-invalid", "SignerInfo carries no encryptedDigest", facts)

    kind = key.get("kind")
    if kind == "rsa":
        facts["key_kind"] = "rsa"
        return _rsa_pkcs1v15_verify(key, signature, signed_bytes, digest_name)
    if kind == "ecdsa":
        facts["key_kind"] = "ecdsa"
        facts["curve"] = key.get("curve", "")
        return ("unsupported-algorithm",
                f"signer key is ECDSA ({key.get('curve') or 'unknown curve'}); this build "
                f"verifies RSASSA-PKCS1-v1_5 only, so the signature is NOT verified",
                facts)
    facts["key_kind"] = str(kind)
    return ("unsupported-algorithm",
            f"signer key algorithm is {key.get('key_oid') or 'unknown'}; "
            f"the signature is NOT verified", facts)


def _verify_signed_data(pe: PE, signed: dict[str, Any],
                        digest_cache: dict[str, bytes]
                        ) -> tuple[str | None, str, dict[str, Any]]:
    """Full chain for one SignedData. (status, detail, facts); status None = verified."""
    facts: dict[str, Any] = {}
    algorithm = (signed.get("content_digest_algo") or "").lower()
    nominal = signed.get("content_digest") or b""
    if not algorithm:
        return ("unsupported-algorithm",
                "SpcIndirectDataContent names no digest algorithm", facts)
    if not nominal:
        return ("unparsed", "no encapsulated digest found in the signature", facts)

    if algorithm not in digest_cache:
        try:
            digest_cache[algorithm] = authenticode_digest(pe, algorithm)
        except ValueError:
            return ("unsupported-algorithm",
                    f"unknown file digest algorithm {algorithm!r}", facts)
    actual = digest_cache[algorithm]
    facts["file_digest"] = actual.hex()
    facts["claimed_digest"] = nominal.hex()

    # step 1: is the nominal digest even the hash of this file?
    if actual != nominal:
        return ("digest-mismatch",
                "file bytes do not match the digest inside SpcIndirectDataContent "
                "(modified after signing, or the table was copied from elsewhere)",
                facts)

    content_octets = signed.get("content_octets") or b""
    content_der = signed.get("content_der") or b""
    if not content_octets:
        return ("unparsed", "the signed content could not be isolated", facts)

    signers = signed.get("signers") or []
    if not signers:
        return ("unparsed", "signedData carries no signerInfo", facts)

    first_failure: tuple[str | None, str, dict[str, Any]] | None = None
    for signer in signers:
        status, detail, signer_facts = _verify_one_signer(signer, content_octets, content_der)
        merged = dict(facts)
        merged.update(signer_facts)
        if status is None:
            return (None, detail, merged)
        if first_failure is None:
            first_failure = (status, detail, merged)
    assert first_failure is not None
    return first_failure


_FAILURE_RANK = {
    "digest-mismatch": 0,
    "signature-invalid": 1,
    "unsupported-algorithm": 2,
    "self-consistent": 3,
    "unparsed": 4,
}


def _better(a: tuple[str | None, str, dict[str, Any]] | None,
            b: tuple[str | None, str, dict[str, Any]] | None
            ) -> tuple[str | None, str, dict[str, Any]] | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if _FAILURE_RANK.get(a[0] or "", 9) <= _FAILURE_RANK.get(b[0] or "", 9) else b


# --------------------------------------------------------------------------- #
# top level
# --------------------------------------------------------------------------- #

def inspect_signature(pe: PE) -> dict[str, Any]:
    out: dict[str, Any] = {
        "present": False,
        "status": "unsigned",
        "detail": ("no IMAGE_DIRECTORY_ENTRY_SECURITY entry: no embedded signature "
                   "(Windows may still trust the file through a system catalog)"),
        "verified": False,
        "signers": [],
        "chain_verified": False,
        "timestamped": False,
    }
    off, size = pe.certificate_table()
    if not off or not size:
        return out

    out["present"] = True
    out["table_offset"] = off
    out["table_size"] = size

    blob = None
    pos = off
    end = off + size
    guard = 0
    while pos + 8 <= end and guard < 16:
        guard += 1
        length = struct.unpack_from("<I", pe.data, pos)[0]
        if length < 8:
            break
        revision, ctype = struct.unpack_from("<HH", pe.data, pos + 4)
        body = pe.data[pos + 8: min(pos + length, len(pe.data))]
        if ctype == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            if pos + length > end:
                # The entry promises more bytes than IMAGE_DIRECTORY_ENTRY_SECURITY
                # reserves (or than the file still holds). Whatever is left is a
                # fragment: parsing it would mean guessing, so refuse to conclude.
                out["status"] = "unparsed"
                out["detail"] = (
                    f"the WIN_CERTIFICATE entry claims {length} bytes but only "
                    f"{end - pos} are inside the declared certificate table "
                    f"(truncated or a doctored Size field)")
                return out
            blob = body
            break
        pos += (length + 7) & ~7

    if blob is None:
        out["status"] = "unparsed"
        out["detail"] = "certificate table present but holds no PKCS#7 blob"
        return out
    if len(blob) < 16:
        out["status"] = "unparsed"
        out["detail"] = "PKCS#7 blob is too short to be meaningful"
        return out

    try:
        root = decode(blob)
        signed = _parse_signed_data(root, blob)
    except (DERError, ValueError, IndexError) as exc:
        out["status"] = "unparsed"
        out["detail"] = f"PKCS#7 could not be decoded: {exc}"
        return out

    if not signed:
        out["status"] = "unparsed"
        out["detail"] = "PKCS#7 has no signedData content"
        return out

    out["digest_algorithm"] = signed.get("content_digest_algo") or ""

    nominal = signed.get("content_digest") or b""
    if signed.get("content_digest_algo"):
        if nominal and len(nominal) > 4 and nominal[:4] == b"\x00\x00\x00\x00":
            out["status"] = "indirect"
            out["detail"] = ("signature carries a zero digest; the file is covered by a "
                             "catalog / external signature instead of an embedded one")
        else:
            cache: dict[str, bytes] = {}
            primary = _verify_signed_data(pe, signed, cache)
            nested = signed.get("nested")
            nested_result = _verify_signed_data(pe, nested, cache) if nested else None

            if (primary and primary[0] is None) or (nested_result and nested_result[0] is None):
                winner = primary if primary and primary[0] is None else nested_result
                out["status"] = "valid"
                out["verified"] = True
                out["detail"] = (
                    f"{out['digest_algorithm'].upper()} image digest matches the signed "
                    f"attributes and the signature verifies against the signer certificate"
                )
                out["verify"] = (winner or (None, "", {}))[2]
            else:
                chosen = _better(primary, nested_result)
                assert chosen is not None
                out["status"] = chosen[0] or "unparsed"
                out["detail"] = chosen[1]
                out["verify"] = chosen[2]
                if primary and primary[2]:
                    out["file_digest"] = primary[2].get("file_digest", "")
                    out["claimed_digest"] = primary[2].get("claimed_digest", "")
    else:
        out["status"] = "unparsed"
        out["detail"] = "no encapsulated digest found in the signature"

    signers = []
    for s in signed.get("signers", []):
        signers.append({
            "subject": s.get("subject", ""),
            "issuer": s.get("issuer", ""),
            "serial": (f"{s['serial_int']:X}" if s.get("serial_int") is not None else ""),
            "not_before": s.get("not_before", ""),
            "not_after": s.get("not_after", ""),
            "digest": s.get("digest", ""),
            "signing": s.get("signing", ""),
            "timestamped": bool(s.get("timestamped")),
            "signature_bytes": len(s.get("signature") or b""),
            "has_signed_attributes": bool(s.get("attrs_der")),
            "key_kind": ((s.get("cert") or {}).get("_spki") or {}).get("kind", ""),
        })
    nested = signed.get("nested")
    if nested:
        for s in nested.get("signers", []):
            signers.append({
                "subject": s.get("subject", ""),
                "issuer": s.get("issuer", ""),
                "serial": (f"{s['serial_int']:X}" if s.get("serial_int") is not None else ""),
                "not_before": s.get("not_before", ""),
                "not_after": s.get("not_after", ""),
                "digest": s.get("digest", ""),
                "signing": s.get("signing", ""),
                "timestamped": bool(s.get("timestamped")),
                "nested": True,
                "signature_bytes": len(s.get("signature") or b""),
                "has_signed_attributes": bool(s.get("attrs_der")),
                "key_kind": ((s.get("cert") or {}).get("_spki") or {}).get("kind", ""),
            })
        out["nested_present"] = True
    out["signers"] = signers
    out["timestamped"] = bool(signed.get("timestamped") or nested and nested.get("timestamped"))
    return out
