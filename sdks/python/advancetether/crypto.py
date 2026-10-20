"""
ATP/1.0 Cryptographic Engine (ATP-SHA256-CTR-HMAC)
100% deterministic, zero-external-dependency authenticated encryption & signing
compatible byte-for-byte across Python, JS/TS, Go, Rust, C, C++, Java, C#, Ruby, and PHP.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
from typing import Dict, Tuple, Optional


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_peer_id(seed: Optional[str] = None) -> str:
    raw = (seed or os.urandom(16).hex()).encode("utf-8")
    digest = sha256_hex(raw)
    return f"atp_{digest[:16]}"


def derive_keys(network_key: str) -> Tuple[bytes, bytes]:
    k_enc = sha256_bytes(("ATP_ENC:" + network_key).encode("utf-8"))
    k_mac = sha256_bytes(("ATP_MAC:" + network_key).encode("utf-8"))
    return k_enc, k_mac


def _keystream_xor(data: bytes, k_enc: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    blocks = (len(data) + 31) // 32
    for counter in range(blocks):
        counter_be = struct.pack(">I", counter)
        block = sha256_bytes(k_enc + nonce + counter_be)
        start = counter * 32
        end = min(start + 32, len(data))
        for i in range(start, end):
            out[i] = data[i] ^ block[i - start]
    return bytes(out)


def encrypt_payload(plaintext_bytes: bytes, network_key: str, nonce_hex: Optional[str] = None) -> bytes:
    k_enc, k_mac = derive_keys(network_key)
    if nonce_hex is not None:
        nonce = bytes.fromhex(nonce_hex)
    else:
        nonce = os.urandom(16)
        nonce_hex = nonce.hex()

    ciphertext = _keystream_xor(plaintext_bytes, k_enc, nonce)
    tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()

    envelope = {
        "enc": "ATP-SHA256-CTR-HMAC",
        "nonce": nonce_hex,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": tag,
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def decrypt_payload(encrypted_json_bytes: bytes, network_key: str) -> bytes:
    k_enc, k_mac = derive_keys(network_key)
    envelope = json.loads(encrypted_json_bytes.decode("utf-8"))
    if envelope.get("enc") != "ATP-SHA256-CTR-HMAC":
        raise ValueError(f"Unsupported encryption scheme: {envelope.get('enc')}")

    nonce = bytes.fromhex(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    expected_tag = hmac.new(k_mac, nonce + ciphertext, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_tag, envelope.get("tag", "")):
        raise ValueError("ATP HMAC authentication tag mismatch")

    return _keystream_xor(ciphertext, k_enc, nonce)


def sign_envelope(envelope: Dict, network_key: str) -> str:
    _, k_mac = derive_keys(network_key)
    canonical = f"{envelope.get('id','')}:{envelope.get('type','')}:{envelope.get('from','')}:{envelope.get('to','')}:{envelope.get('ts',0)}"
    return hmac.new(k_mac, canonical.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def verify_envelope(envelope: Dict, network_key: str) -> bool:
    sig = envelope.get("sig", "")
    if not sig:
        return False
    expected = sign_envelope(envelope, network_key)
    return hmac.compare_digest(sig, expected)
