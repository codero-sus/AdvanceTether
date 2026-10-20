"""
ATP/1.0 Binary Wire Protocol Framing & Envelope Codec
"""

import json
import os
import socket
import struct
import time
from typing import Any, Dict, Optional, Tuple

from .crypto import decrypt_payload, encrypt_payload, sign_envelope

MAGIC = b"AT2P"
VERSION = 1
HEADER_SIZE = 12
MAX_PAYLOAD_SIZE = 16 * 1024 * 1024  # 16 MiB

FLAG_ENCRYPTED = 0x01
FLAG_COMPRESSED = 0x02
FLAG_BINARY = 0x04
FLAG_ACK_REQ = 0x08


class PacketType:
    HELLO = 0x01
    HELLO_ACK = 0x02
    PING = 0x03
    PONG = 0x04
    DISCOVER = 0x05
    PEER_LIST = 0x06
    DHT_PUT = 0x07
    DHT_GET = 0x08
    DHT_RES = 0x09
    MSG = 0x0A
    PUBSUB_SUB = 0x0B
    PUBSUB_PUB = 0x0C
    FILE_OFFER = 0x0D
    FILE_CHUNK = 0x0E
    FILE_ACK = 0x0F
    TUNNEL_OPEN = 0x10
    TUNNEL_DATA = 0x11
    TUNNEL_CLOSE = 0x12
    HOLE_PUNCH = 0x13

    NAMES = {
        0x01: "HELLO",
        0x02: "HELLO_ACK",
        0x03: "PING",
        0x04: "PONG",
        0x05: "DISCOVER",
        0x06: "PEER_LIST",
        0x07: "DHT_PUT",
        0x08: "DHT_GET",
        0x09: "DHT_RES",
        0x0A: "MSG",
        0x0B: "PUBSUB_SUB",
        0x0C: "PUBSUB_PUB",
        0x0D: "FILE_OFFER",
        0x0E: "FILE_CHUNK",
        0x0F: "FILE_ACK",
        0x10: "TUNNEL_OPEN",
        0x11: "TUNNEL_DATA",
        0x12: "TUNNEL_CLOSE",
        0x13: "HOLE_PUNCH",
    }

    BY_NAME = {v: k for k, v in NAMES.items()}


def make_envelope(
    msg_type: int,
    from_peer: str,
    body: Dict[str, Any],
    to_peer: str = "*",
    lang: str = "python",
    ttl: int = 6,
    network_key: str = "advancetether-default-key",
    msg_id: Optional[str] = None,
) -> Dict[str, Any]:
    type_name = PacketType.NAMES.get(msg_type, "MSG")
    env = {
        "v": VERSION,
        "id": msg_id or f"msg_{os.urandom(8).hex()}",
        "type": type_name,
        "from": from_peer,
        "to": to_peer,
        "lang": lang,
        "ts": int(time.time() * 1000),
        "ttl": ttl,
        "body": body,
    }
    env["sig"] = sign_envelope(env, network_key)
    return env


def encode_frame(
    msg_type: int,
    envelope: Dict[str, Any],
    encrypt: bool = False,
    network_key: str = "advancetether-default-key",
    flags: int = 0,
    nonce_hex: Optional[str] = None,
) -> bytes:
    raw_json = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if encrypt:
        flags |= FLAG_ENCRYPTED
        payload = encrypt_payload(raw_json, network_key, nonce_hex=nonce_hex)
    else:
        payload = raw_json

    header = struct.pack(">4sBBBB I", MAGIC, VERSION, flags, msg_type, 0, len(payload))
    return header + payload


def decode_frame_header(header_bytes: bytes) -> Tuple[int, int, int, int]:
    if len(header_bytes) != HEADER_SIZE:
        raise ValueError(f"Expected {HEADER_SIZE} header bytes, got {len(header_bytes)}")
    magic, version, flags, msg_type, _reserved, length = struct.unpack(">4sBBBB I", header_bytes)
    if magic != MAGIC:
        raise ValueError(f"Invalid ATP magic bytes: {magic!r}")
    if version != VERSION:
        raise ValueError(f"Unsupported ATP version: {version}")
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload length {length} exceeds maximum {MAX_PAYLOAD_SIZE}")
    return version, flags, msg_type, length


def decode_frame(
    frame_bytes: bytes,
    network_key: str = "advancetether-default-key",
) -> Tuple[int, int, Dict[str, Any]]:
    version, flags, msg_type, length = decode_frame_header(frame_bytes[:HEADER_SIZE])
    payload = frame_bytes[HEADER_SIZE : HEADER_SIZE + length]
    if len(payload) < length:
        raise ValueError("Truncated ATP payload")
    if flags & FLAG_ENCRYPTED:
        payload = decrypt_payload(payload, network_key)
    envelope = json.loads(payload.decode("utf-8"))
    return msg_type, flags, envelope


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_frame_from_socket(
    sock: socket.socket,
    network_key: str = "advancetether-default-key",
) -> Optional[Tuple[int, int, Dict[str, Any]]]:
    header = _recv_exact(sock, HEADER_SIZE)
    if not header:
        return None
    _version, flags, msg_type, length = decode_frame_header(header)
    payload = _recv_exact(sock, length)
    if payload is None:
        return None
    if flags & FLAG_ENCRYPTED:
        payload = decrypt_payload(payload, network_key)
    envelope = json.loads(payload.decode("utf-8"))
    return msg_type, flags, envelope
