"""
ATP/1.0 Kademlia XOR Distributed Hash Table (DHT) & Routing Table
"""

import hashlib
import time
from typing import Any, Dict, List, Optional


def id_to_uint64(peer_id: str) -> int:
    clean = peer_id[4:] if peer_id.startswith("atp_") else peer_id
    clean = (clean + "0" * 16)[:16]
    try:
        return int(clean, 16)
    except ValueError:
        digest = hashlib.sha256(peer_id.encode("utf-8")).hexdigest()[:16]
        return int(digest, 16)


def key_to_uint64(key: str) -> int:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return int(digest, 16)


def xor_distance(id_a: str, id_b: str) -> int:
    return id_to_uint64(id_a) ^ id_to_uint64(id_b)


class DHTNode:
    def __init__(self, self_peer_id: str, k_bucket_size: int = 20):
        self.self_peer_id = self_peer_id
        self.k_bucket_size = k_bucket_size
        self.store: Dict[str, Dict[str, Any]] = {}
        self.routing_table: Dict[str, Dict[str, Any]] = {}

    def update_peer(self, peer_id: str, host: str, port: int, lang: str = "unknown", name: str = "") -> None:
        if not peer_id or peer_id == self.self_peer_id:
            return
        dist = xor_distance(self.self_peer_id, peer_id)
        self.routing_table[peer_id] = {
            "peer_id": peer_id,
            "host": host,
            "port": int(port),
            "lang": lang,
            "name": name or peer_id,
            "xor_distance": dist,
            "last_seen": int(time.time() * 1000),
        }

    def remove_peer(self, peer_id: str) -> None:
        self.routing_table.pop(peer_id, None)

    def put(self, key: str, value: Any, origin: str = "", ttl_sec: int = 3600) -> Dict[str, Any]:
        record = {
            "key": key,
            "key_hash": f"{key_to_uint64(key):016x}",
            "value": value,
            "origin": origin or self.self_peer_id,
            "stored_at": int(time.time() * 1000),
            "expires_at": int((time.time() + ttl_sec) * 1000),
        }
        self.store[key] = record
        return record

    def get(self, key: str) -> Optional[Any]:
        record = self.store.get(key)
        if not record:
            return None
        if record["expires_at"] < int(time.time() * 1000):
            self.store.pop(key, None)
            return None
        return record["value"]

    def closest_peers(self, target_key_or_id: str, count: int = 8) -> List[Dict[str, Any]]:
        if target_key_or_id.startswith("atp_"):
            target_int = id_to_uint64(target_key_or_id)
        else:
            target_int = key_to_uint64(target_key_or_id)
        peers = list(self.routing_table.values())
        peers.sort(key=lambda p: id_to_uint64(p["peer_id"]) ^ target_int)
        return peers[:count]
