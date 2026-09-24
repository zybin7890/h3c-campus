"""Byte-level H3C 802.1X framing; no network or credential storage operations.

An independent implementation of the observed legacy version-field format.
Compatibility with any particular authentication server requires a live test.
"""

import base64
import binascii
import hashlib
import secrets
import struct

_VERSION_KEY = b"Oly5D62FaE94W7"
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}


def _byte(value: int, name: str) -> int:
    if not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError(f"{name} must be an unsigned byte")
    return value


def _mask(value: bytes, key: bytes) -> bytes:
    """Combine forward and backward repeating-key XOR in a single pass."""
    last = len(value) - 1
    return bytes(value[pos] ^ key[pos % len(key)] ^ key[(last - pos) % len(key)]
                 for pos in range(len(value)))


def decode_version_extension(extension32: bytes) -> bytes:
    if len(extension32) != 32 or extension32[:2] != b"\x06\x07" or extension32[-2:] != b"  ":
        raise ValueError("version extension must be 06 07, 28 base64 bytes, two spaces")
    try:
        encoded = base64.b64decode(extension32[2:30], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid version base64") from exc
    if len(encoded) != 20 or base64.b64encode(encoded) != extension32[2:30]:
        raise ValueError("version base64 must canonically encode 20 bytes")
    decoded = _mask(encoded, _VERSION_KEY)
    nonce = int.from_bytes(decoded[16:], "big")
    return _mask(decoded[:16], f"{nonce:08x}".encode("ascii"))


def encode_version_extension(version16: bytes, nonce: int | None = None) -> bytes:
    if len(version16) != 16:
        raise ValueError("version must contain exactly 16 bytes")
    if nonce is None:
        nonce = secrets.randbits(32)
    if not isinstance(nonce, int) or not 0 <= nonce <= 0xFFFFFFFF:
        raise ValueError("nonce must be an unsigned 32-bit integer")
    mixed = _mask(version16, f"{nonce:08x}".encode("ascii"))
    body = mixed + nonce.to_bytes(4, "big")
    return b"\x06\x07" + base64.b64encode(_mask(body, _VERSION_KEY)) + b"  "


def parse_frame(frame: bytes) -> dict | None:
    """Return a bounded EAPOL view, or None for malformed/unrelated traffic."""
    if len(frame) < 14:
        return None
    ether_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    tags = 0
    while ether_type in _VLAN_TYPES:
        if tags == 2 or len(frame) < offset + 4:
            return None
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
        tags += 1
    if ether_type != 0x888E or len(frame) < offset + 4:
        return None
    version, packet_type, length = struct.unpack_from("!BBH", frame, offset)
    begin = offset + 4
    if len(frame) < begin + length:
        return None
    body = frame[begin:begin + length]
    result = {"dst": frame[:6], "src": frame[6:12], "version": version,
              "eapol_type": packet_type, "eap_code": None, "eap_id": None,
              "eap_type": None, "eap_data": b""}
    if packet_type != 0:
        return result
    if len(body) < 4:
        return None
    code, identifier, eap_length = struct.unpack_from("!BBH", body)
    if eap_length < 4 or eap_length > len(body):
        return None
    data = body[4:eap_length]
    if code in (1, 2):
        if not data:
            return None
        result["eap_type"] = data[0]
        data = data[1:]
    result.update(eap_code=code, eap_id=identifier, eap_data=data)
    return result


def make_frame(src: bytes, dst: bytes, eapol_type: int, payload: bytes = b"", version: int = 1) -> bytes:
    if len(src) != 6 or len(dst) != 6:
        raise ValueError("MAC addresses must contain six bytes")
    _byte(eapol_type, "eapol_type")
    _byte(version, "version")
    if len(payload) > 65535:
        raise ValueError("EAPOL payload is too large")
    frame = dst + src + b"\x88\x8e" + struct.pack("!BBH", version, eapol_type, len(payload)) + payload
    return frame.ljust(60, b"\0")


def make_response(eap_id: int, eap_type: int, data: bytes) -> bytes:
    _byte(eap_id, "eap_id")
    _byte(eap_type, "eap_type")
    if len(data) > 65530:
        raise ValueError("EAP response data is too large")
    return struct.pack("!BBHB", 2, eap_id, 5 + len(data), eap_type) + data


def identity_data(username: bytes, version16: bytes, nonce: int | None = None) -> bytes:
    return encode_version_extension(version16, nonce) + username


def md5_data(eap_id: int, password: bytes, challenge: bytes, username: bytes) -> bytes:
    _byte(eap_id, "eap_id")
    if not 1 <= len(challenge) <= 255:
        raise ValueError("MD5 challenge length must be 1 to 255 bytes")
    digest = hashlib.md5(bytes([eap_id]) + password + challenge).digest()
    return b"\x10" + digest + username
