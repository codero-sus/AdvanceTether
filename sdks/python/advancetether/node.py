"""
ATP/1.0 Full Peer-to-Peer Node Implementation for Python
"""

import base64
import hashlib
import os
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .crypto import generate_peer_id, sha256_hex, verify_envelope
from .dht import DHTNode
from .protocol import (
    PacketType,
    decode_frame,
    encode_frame,
    make_envelope,
    read_frame_from_socket,
)


class AdvanceTetherNode:
    def __init__(
        self,
        name: str = "py-node",
        host: str = "127.0.0.1",
        port: int = 0,
        udp_port: int = 0,
        network_key: str = "advancetether-default-key",
        peer_id: Optional[str] = None,
        encrypt: bool = True,
        download_dir: Optional[str] = None,
    ):
        self.name = name
        self.lang = "python"
        self.host = host
        self.port = port
        self.udp_port = udp_port
        self.network_key = network_key
        self.peer_id = peer_id or generate_peer_id(f"python:{name}:{time.time_ns()}")
        self.encrypt = encrypt
        self.download_dir = download_dir or "/tmp/advancetether_downloads"
        os.makedirs(self.download_dir, exist_ok=True)

        self.dht = DHTNode(self.peer_id)
        self.running = False

        self._server_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None
        self._peers_lock = threading.RLock()
        self.peers: Dict[str, Dict[str, Any]] = {}  # peer_id -> {sock, host, port, lang, name, rtt_ms}
        self.seen_msg_ids: Set[str] = set()
        self.subscriptions: Set[str] = set()
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.incoming_files: Dict[str, Dict[str, Any]] = {}
        self.completed_files: Dict[str, Dict[str, Any]] = {}
        self.tunnels: Dict[str, Dict[str, Any]] = {}
        self.received_messages: List[Dict[str, Any]] = []
        self.pubsub_messages: List[Dict[str, Any]] = []
        self.stats = {
            "frames_sent": 0,
            "frames_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
        }

    def on(self, event: str, handler: Callable) -> None:
        self.event_handlers.setdefault(event, []).append(handler)

    def _emit(self, event: str, data: Any) -> None:
        for handler in self.event_handlers.get(event, []):
            try:
                handler(data)
            except Exception:
                pass

    def start(self) -> Tuple[str, int]:
        if self.running:
            return self.host, self.port

        self.running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0" if self.host == "0.0.0.0" else self.host, self.port))
        self._server_sock.listen(64)
        self.port = self._server_sock.getsockname()[1]

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
        self._udp_sock.bind(("0.0.0.0" if self.host == "0.0.0.0" else self.host, self.udp_port))
        self.udp_port = self._udp_sock.getsockname()[1]

        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._udp_loop, daemon=True).start()
        return self.host, self.port

    def stop(self) -> None:
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass
        with self._peers_lock:
            for p in list(self.peers.values()):
                sock = p.get("sock")
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        sock.close()
                    except Exception:
                        pass
            self.peers.clear()

    def _accept_loop(self) -> None:
        while self.running and self._server_sock:
            try:
                client_sock, addr = self._server_sock.accept()
                threading.Thread(
                    target=self._client_loop,
                    args=(client_sock, addr[0], addr[1], False),
                    daemon=True,
                ).start()
            except Exception:
                if not self.running:
                    break

    def _udp_loop(self) -> None:
        while self.running and self._udp_sock:
            try:
                data, addr = self._udp_sock.recvfrom(65535)
                msg_type, _flags, env = decode_frame(data, self.network_key)
                self._handle_envelope(msg_type, env, None, addr[0], addr[1], is_udp=True)
            except Exception:
                if not self.running:
                    break

    def connect(self, host: str, port: int, timeout: float = 5.0) -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.settimeout(None)

        hello_env = make_envelope(
            PacketType.HELLO,
            self.peer_id,
            {
                "peer_id": self.peer_id,
                "name": self.name,
                "lang": self.lang,
                "host": self.host,
                "port": self.port,
                "udp_port": self.udp_port,
                "capabilities": ["msg", "dht", "pubsub", "file", "tunnel", "e2ee"],
            },
            lang=self.lang,
            network_key=self.network_key,
        )
        self._send_raw_frame(sock, PacketType.HELLO, hello_env)

        # Read HELLO_ACK synchronously so caller immediately gets remote peer_id
        res = read_frame_from_socket(sock, self.network_key)
        if not res:
            sock.close()
            return None
        msg_type, _flags, env = res
        remote_id = env.get("from") or env.get("body", {}).get("peer_id")
        body = env.get("body", {})
        remote_port = int(body.get("port") or port)
        remote_lang = body.get("lang") or env.get("lang", "unknown")
        remote_name = body.get("name") or remote_id

        if remote_id:
            with self._peers_lock:
                self.peers[remote_id] = {
                    "peer_id": remote_id,
                    "sock": sock,
                    "host": host,
                    "port": remote_port,
                    "lang": remote_lang,
                    "name": remote_name,
                    "rtt_ms": 1.0,
                    "lock": threading.Lock(),
                }
            self.dht.update_peer(remote_id, host, remote_port, remote_lang, remote_name)
            self._emit("peer_connected", self.peers[remote_id])

        threading.Thread(
            target=self._client_loop,
            args=(sock, host, remote_port, True, remote_id),
            daemon=True,
        ).start()
        return remote_id

    def _send_raw_frame(
        self,
        sock: socket.socket,
        msg_type: int,
        envelope: Dict[str, Any],
        lock: Optional[threading.Lock] = None,
    ) -> bool:
        frame = encode_frame(
            msg_type,
            envelope,
            encrypt=self.encrypt,
            network_key=self.network_key,
        )
        try:
            if lock:
                with lock:
                    sock.sendall(frame)
            else:
                sock.sendall(frame)
            self.stats["frames_sent"] += 1
            self.stats["bytes_sent"] += len(frame)
            return True
        except Exception:
            return False

    def _send_to_peer(self, peer_id: str, msg_type: int, body: Dict[str, Any]) -> bool:
        with self._peers_lock:
            peer = self.peers.get(peer_id)
        if not peer or not peer.get("sock"):
            return False
        env = make_envelope(
            msg_type,
            self.peer_id,
            body,
            to_peer=peer_id,
            lang=self.lang,
            network_key=self.network_key,
        )
        return self._send_raw_frame(peer["sock"], msg_type, env, peer.get("lock"))

    def _broadcast(self, msg_type: int, body: Dict[str, Any], exclude_peer: Optional[str] = None, msg_id: Optional[str] = None) -> int:
        env = make_envelope(
            msg_type,
            self.peer_id,
            body,
            to_peer="*",
            lang=self.lang,
            network_key=self.network_key,
            msg_id=msg_id,
        )
        self.seen_msg_ids.add(env["id"])
        sent = 0
        with self._peers_lock:
            peers_list = list(self.peers.values())
        for p in peers_list:
            if p["peer_id"] == exclude_peer:
                continue
            if self._send_raw_frame(p["sock"], msg_type, env, p.get("lock")):
                sent += 1
        return sent

    def _client_loop(
        self,
        sock: socket.socket,
        host: str,
        port: int,
        already_handshook: bool,
        known_peer_id: Optional[str] = None,
    ) -> None:
        current_peer_id = known_peer_id
        try:
            while self.running:
                res = read_frame_from_socket(sock, self.network_key)
                if not res:
                    break
                msg_type, _flags, env = res
                self.stats["frames_received"] += 1
                if not verify_envelope(env, self.network_key):
                    continue
                sender = env.get("from")
                if sender and not current_peer_id:
                    current_peer_id = sender
                self._handle_envelope(msg_type, env, sock, host, port)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            if current_peer_id:
                with self._peers_lock:
                    existing = self.peers.get(current_peer_id)
                    if existing and existing.get("sock") is sock:
                        self.peers.pop(current_peer_id, None)
                self._emit("peer_disconnected", {"peer_id": current_peer_id})

    def _handle_envelope(
        self,
        msg_type: int,
        env: Dict[str, Any],
        sock: Optional[socket.socket],
        host: str,
        port: int,
        is_udp: bool = False,
    ) -> None:
        msg_id = env.get("id", "")
        sender_id = env.get("from", "")
        body = env.get("body") or {}

        if msg_type == PacketType.HELLO:
            remote_port = int(body.get("port") or port)
            remote_lang = body.get("lang") or env.get("lang", "unknown")
            remote_name = body.get("name") or sender_id
            if sock and sender_id:
                with self._peers_lock:
                    self.peers[sender_id] = {
                        "peer_id": sender_id,
                        "sock": sock,
                        "host": host,
                        "port": remote_port,
                        "lang": remote_lang,
                        "name": remote_name,
                        "rtt_ms": 1.0,
                        "lock": threading.Lock(),
                    }
                self.dht.update_peer(sender_id, host, remote_port, remote_lang, remote_name)
                ack = make_envelope(
                    PacketType.HELLO_ACK,
                    self.peer_id,
                    {
                        "peer_id": self.peer_id,
                        "name": self.name,
                        "lang": self.lang,
                        "host": self.host,
                        "port": self.port,
                        "udp_port": self.udp_port,
                        "peers": self.dht.closest_peers(sender_id, 10),
                    },
                    to_peer=sender_id,
                    lang=self.lang,
                    network_key=self.network_key,
                )
                self._send_raw_frame(sock, PacketType.HELLO_ACK, ack, self.peers[sender_id]["lock"])
                self._emit("peer_connected", self.peers[sender_id])

        elif msg_type == PacketType.PING:
            pong_body = {"ping_id": body.get("ping_id"), "sent_ts": body.get("sent_ts", 0)}
            if sock:
                pong = make_envelope(
                    PacketType.PONG,
                    self.peer_id,
                    pong_body,
                    to_peer=sender_id,
                    lang=self.lang,
                    network_key=self.network_key,
                )
                self._send_raw_frame(sock, PacketType.PONG, pong)

        elif msg_type == PacketType.PONG:
            sent_ts = body.get("sent_ts", 0)
            if sent_ts and sender_id in self.peers:
                rtt = max(0.1, time.time() * 1000.0 - float(sent_ts))
                self.peers[sender_id]["rtt_ms"] = round(rtt, 2)
                self._emit("pong", {"from": sender_id, "rtt_ms": rtt})

        elif msg_type == PacketType.DISCOVER:
            peer_list = list(self.dht.routing_table.values())
            resp = make_envelope(
                PacketType.PEER_LIST,
                self.peer_id,
                {
                    "peer_id": self.peer_id,
                    "name": self.name,
                    "lang": self.lang,
                    "host": self.host,
                    "port": self.port,
                    "peers": peer_list,
                },
                to_peer=sender_id,
                lang=self.lang,
                network_key=self.network_key,
            )
            if is_udp and self._udp_sock:
                frame = encode_frame(PacketType.PEER_LIST, resp, encrypt=self.encrypt, network_key=self.network_key)
                self._udp_sock.sendto(frame, (host, port))
            elif sock:
                self._send_raw_frame(sock, PacketType.PEER_LIST, resp)

        elif msg_type == PacketType.PEER_LIST:
            for p in body.get("peers", []):
                pid = p.get("peer_id")
                if pid and pid != self.peer_id:
                    self.dht.update_peer(pid, p.get("host", "127.0.0.1"), int(p.get("port", 0)), p.get("lang", "unknown"), p.get("name", pid))
            self._emit("peer_list", body)

        elif msg_type == PacketType.DHT_PUT:
            key = body.get("key")
            val = body.get("value")
            if key is not None:
                rec = self.dht.put(str(key), val, origin=sender_id)
                self._emit("dht_put", rec)
                if sock:
                    ack = make_envelope(
                        PacketType.DHT_RES,
                        self.peer_id,
                        {"key": key, "value": val, "found": True, "stored": True},
                        to_peer=sender_id,
                        lang=self.lang,
                        network_key=self.network_key,
                    )
                    self._send_raw_frame(sock, PacketType.DHT_RES, ack)

        elif msg_type == PacketType.DHT_GET:
            key = str(body.get("key", ""))
            val = self.dht.get(key)
            if sock:
                res_env = make_envelope(
                    PacketType.DHT_RES,
                    self.peer_id,
                    {
                        "key": key,
                        "value": val,
                        "found": val is not None,
                        "peers": self.dht.closest_peers(key, 6),
                    },
                    to_peer=sender_id,
                    lang=self.lang,
                    network_key=self.network_key,
                )
                self._send_raw_frame(sock, PacketType.DHT_RES, res_env)

        elif msg_type == PacketType.DHT_RES:
            if body.get("found") and body.get("key"):
                self.dht.put(str(body["key"]), body.get("value"), origin=sender_id)
            self._emit("dht_res", body)

        elif msg_type == PacketType.MSG:
            if msg_id in self.seen_msg_ids:
                return
            self.seen_msg_ids.add(msg_id)
            record = {
                "id": msg_id,
                "from": sender_id,
                "to": env.get("to"),
                "lang": env.get("lang"),
                "ts": env.get("ts"),
                "body": body,
            }
            self.received_messages.append(record)
            self._emit("message", record)

            # Auto-respond if RPC ping/echo requested
            rpc = body.get("rpc")
            if rpc == "echo" and sock:
                reply = make_envelope(
                    PacketType.MSG,
                    self.peer_id,
                    {"text": f"Echo from {self.name} ({self.lang}): {body.get('text', '')}", "rpc_reply": msg_id},
                    to_peer=sender_id,
                    lang=self.lang,
                    network_key=self.network_key,
                )
                self._send_raw_frame(sock, PacketType.MSG, reply)

        elif msg_type == PacketType.PUBSUB_SUB:
            topic = body.get("topic")
            if topic:
                self._emit("pubsub_sub", {"peer_id": sender_id, "topic": topic})

        elif msg_type == PacketType.PUBSUB_PUB:
            if msg_id in self.seen_msg_ids:
                return
            self.seen_msg_ids.add(msg_id)
            topic = body.get("topic", "general")
            event_data = {
                "id": msg_id,
                "from": sender_id,
                "lang": env.get("lang"),
                "topic": topic,
                "data": body.get("data"),
                "ts": env.get("ts"),
            }
            if topic in self.subscriptions or "*" in self.subscriptions:
                self.pubsub_messages.append(event_data)
                self._emit("pubsub_message", event_data)
            # Gossip forward if TTL > 1
            ttl = int(env.get("ttl", 1))
            if ttl > 1:
                self._broadcast(PacketType.PUBSUB_PUB, body, exclude_peer=sender_id, msg_id=msg_id)

        elif msg_type == PacketType.FILE_OFFER:
            tid = body["transfer_id"]
            self.incoming_files[tid] = {
                "transfer_id": tid,
                "filename": os.path.basename(body.get("filename", f"{tid}.bin")),
                "size": int(body.get("size", 0)),
                "sha256": body.get("sha256", ""),
                "total_chunks": int(body.get("total_chunks", 1)),
                "chunks": {},
                "from": sender_id,
            }
            self._emit("file_offer", self.incoming_files[tid])
            if int(body.get("total_chunks", 1)) == 0:
                self._finalize_file(tid, sender_id, sock)

        elif msg_type == PacketType.FILE_CHUNK:
            tid = body.get("transfer_id")
            info = self.incoming_files.get(tid)
            if info:
                idx = int(body.get("chunk_index", 0))
                raw_chunk = base64.b64decode(body.get("data_b64", ""))
                info["chunks"][idx] = raw_chunk
                if len(info["chunks"]) >= info["total_chunks"]:
                    self._finalize_file(tid, sender_id, sock)

        elif msg_type == PacketType.FILE_ACK:
            self._emit("file_ack", body)

        elif msg_type == PacketType.TUNNEL_OPEN:
            tid = body.get("tunnel_id")
            target_host = body.get("target_host", "127.0.0.1")
            target_port = int(body.get("target_port", 0))
            self.tunnels[tid] = {
                "tunnel_id": tid,
                "peer_id": sender_id,
                "target_host": target_host,
                "target_port": target_port,
                "received_bytes": bytearray(),
                "status": "OPEN",
            }
            self._emit("tunnel_open", self.tunnels[tid])

        elif msg_type == PacketType.TUNNEL_DATA:
            tid = body.get("tunnel_id")
            raw_bytes = base64.b64decode(body.get("data_b64", ""))
            tun = self.tunnels.setdefault(
                tid,
                {"tunnel_id": tid, "peer_id": sender_id, "received_bytes": bytearray(), "status": "OPEN"},
            )
            tun["received_bytes"].extend(raw_bytes)
            self._emit("tunnel_data", {"tunnel_id": tid, "from": sender_id, "data": raw_bytes})
            if body.get("echo", False) and sock:
                ack_env = make_envelope(
                    PacketType.TUNNEL_DATA,
                    self.peer_id,
                    {
                        "tunnel_id": tid,
                        "seq": int(body.get("seq", 0)) + 1,
                        "data_b64": base64.b64encode(b"TETHER_ACK:" + raw_bytes).decode("ascii"),
                        "echo": False,
                    },
                    to_peer=sender_id,
                    lang=self.lang,
                    network_key=self.network_key,
                )
                self._send_raw_frame(sock, PacketType.TUNNEL_DATA, ack_env)

        elif msg_type == PacketType.TUNNEL_CLOSE:
            tid = body.get("tunnel_id")
            if tid in self.tunnels:
                self.tunnels[tid]["status"] = "CLOSED"
            self._emit("tunnel_close", body)

        elif msg_type == PacketType.HOLE_PUNCH:
            self._emit("hole_punch", body)

    def _finalize_file(self, tid: str, sender_id: str, sock: Optional[socket.socket]) -> None:
        info = self.incoming_files.get(tid)
        if not info:
            return
        ordered = b"".join(info["chunks"][i] for i in range(info["total_chunks"]))
        actual_hash = sha256_hex(ordered)
        verified = (actual_hash == info["sha256"]) if info["sha256"] else True
        dest_path = os.path.join(self.download_dir, info["filename"])
        with open(dest_path, "wb") as f:
            f.write(ordered)
        result = {
            "transfer_id": tid,
            "filename": info["filename"],
            "path": dest_path,
            "size": len(ordered),
            "sha256": actual_hash,
            "verified": verified,
            "from": sender_id,
        }
        self.completed_files[tid] = result
        self._emit("file_complete", result)
        if sock:
            ack = make_envelope(
                PacketType.FILE_ACK,
                self.peer_id,
                {"transfer_id": tid, "filename": info["filename"], "sha256": actual_hash, "verified": verified},
                to_peer=sender_id,
                lang=self.lang,
                network_key=self.network_key,
            )
            self._send_raw_frame(sock, PacketType.FILE_ACK, ack)

    # High-level API
    def send_message(self, peer_id: str, text: str, rpc: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> bool:
        body: Dict[str, Any] = {"text": text}
        if rpc:
            body["rpc"] = rpc
        if extra:
            body.update(extra)
        return self._send_to_peer(peer_id, PacketType.MSG, body)

    def ping(self, peer_id: str) -> bool:
        return self._send_to_peer(
            peer_id,
            PacketType.PING,
            {"ping_id": f"ping_{os.urandom(4).hex()}", "sent_ts": time.time() * 1000.0},
        )

    def dht_put(self, key: str, value: Any) -> Dict[str, Any]:
        rec = self.dht.put(key, value, origin=self.peer_id)
        self._broadcast(PacketType.DHT_PUT, {"key": key, "value": value})
        return rec

    def dht_get(self, key: str) -> Optional[Any]:
        local = self.dht.get(key)
        if local is not None:
            return local
        self._broadcast(PacketType.DHT_GET, {"key": key})
        return None

    def subscribe(self, topic: str) -> None:
        self.subscriptions.add(topic)
        self._broadcast(PacketType.PUBSUB_SUB, {"topic": topic})

    def publish(self, topic: str, data: Any) -> int:
        event = {
            "id": f"pub_{os.urandom(6).hex()}",
            "from": self.peer_id,
            "lang": self.lang,
            "topic": topic,
            "data": data,
            "ts": int(time.time() * 1000),
        }
        if topic in self.subscriptions or "*" in self.subscriptions:
            self.pubsub_messages.append(event)
            self._emit("pubsub_message", event)
        return self._broadcast(PacketType.PUBSUB_PUB, {"topic": topic, "data": data}, msg_id=event["id"])

    def send_file(self, peer_id: str, filepath: str, chunk_size: int = 16384) -> Optional[str]:
        if not os.path.isfile(filepath):
            return None
        with open(filepath, "rb") as f:
            content = f.read()
        return self.send_file_bytes(peer_id, os.path.basename(filepath), content, chunk_size=chunk_size)

    def send_file_bytes(self, peer_id: str, filename: str, content: bytes, chunk_size: int = 16384) -> Optional[str]:
        tid = f"file_{os.urandom(6).hex()}"
        digest = sha256_hex(content)
        chunks = [content[i : i + chunk_size] for i in range(0, len(content), chunk_size)] or [b""]

        ok = self._send_to_peer(
            peer_id,
            PacketType.FILE_OFFER,
            {
                "transfer_id": tid,
                "filename": filename,
                "size": len(content),
                "sha256": digest,
                "total_chunks": len(chunks),
            },
        )
        if not ok:
            return None

        for idx, ch in enumerate(chunks):
            self._send_to_peer(
                peer_id,
                PacketType.FILE_CHUNK,
                {
                    "transfer_id": tid,
                    "chunk_index": idx,
                    "data_b64": base64.b64encode(ch).decode("ascii"),
                    "chunk_sha256": sha256_hex(ch),
                },
            )
        return tid

    def open_tunnel(self, peer_id: str, target_host: str = "127.0.0.1", target_port: int = 8080) -> Optional[str]:
        tid = f"tun_{os.urandom(6).hex()}"
        self.tunnels[tid] = {
            "tunnel_id": tid,
            "peer_id": peer_id,
            "target_host": target_host,
            "target_port": target_port,
            "received_bytes": bytearray(),
            "status": "OPEN",
        }
        if self._send_to_peer(
            peer_id,
            PacketType.TUNNEL_OPEN,
            {"tunnel_id": tid, "target_host": target_host, "target_port": target_port},
        ):
            return tid
        return None

    def send_tunnel_data(self, peer_id: str, tunnel_id: str, data: bytes, echo: bool = True) -> bool:
        return self._send_to_peer(
            peer_id,
            PacketType.TUNNEL_DATA,
            {
                "tunnel_id": tunnel_id,
                "seq": 1,
                "data_b64": base64.b64encode(data).decode("ascii"),
                "echo": echo,
            },
        )

    def close_tunnel(self, peer_id: str, tunnel_id: str) -> bool:
        if tunnel_id in self.tunnels:
            self.tunnels[tunnel_id]["status"] = "CLOSED"
        return self._send_to_peer(
            peer_id,
            PacketType.TUNNEL_CLOSE,
            {"tunnel_id": tunnel_id, "reason": "closed_by_peer"},
        )
