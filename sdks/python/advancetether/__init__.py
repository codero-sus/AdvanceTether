"""
AdvanceTether Python SDK (ATP/1.0)
Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer & Network Tunneling.
"""

from .protocol import (
    MAGIC,
    VERSION,
    HEADER_SIZE,
    FLAG_ENCRYPTED,
    FLAG_COMPRESSED,
    FLAG_BINARY,
    FLAG_ACK_REQ,
     PacketType,
    encode_frame,
    decode_frame,
    decode_frame_header,
    read_frame_from_socket,
    make_envelope,
)
from .crypto import (
    generate_peer_id,
    derive_keys,
    encrypt_payload,
    decrypt_payload,
    sign_envelope,
    verify_envelope,
    sha256_hex,
)
from .dht import (
    xor_distance,
    id_to_uint64,
    key_to_uint64,
    DHTNode,
)
from .node import AdvanceTetherNode

__version__ = "1.0.0"
__all__ = [
    "MAGIC",
    "VERSION",
    "HEADER_SIZE",
    "FLAG_ENCRYPTED",
    "FLAG_COMPRESSED",
    "FLAG_BINARY",
    "FLAG_ACK_REQ",
    "PacketType",
    "encode_frame",
    "decode_frame_header",
    "read_frame_from_socket",
    "make_envelope",
    "generate_peer_id",
    "derive_keys",
    "encrypt_payload",
    "decrypt_payload",
    "sign_envelope",
    "verify_envelope",
    "sha256_hex",
    "xor_distance",
    "id_to_uint64",
    "key_to_uint64",
    "DHTNode",
    "AdvanceTetherNode",
]
