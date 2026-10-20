"""
AdvanceTether Python CLI Entrypoint
"""

import argparse
import json
import sys
import time

from .node import AdvanceTetherNode


def main() -> int:
    parser = argparse.ArgumentParser(description="AdvanceTether Python P2P Node (ATP/1.0)")
    parser.add_argument("--name", default="py-peer", help="Peer node name")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=0, help="Bind TCP port")
    parser.add_argument("--connect", help="Connect to remote peer host:port")
    parser.add_argument("--key", default="advancetether-default-key", help="Shared network key")
    parser.add_argument("--send", help="Send a direct message after connecting")
    parser.add_argument("--dht-put", help="Store key=value in DHT")
    parser.add_argument("--pub", help="Publish topic:message")
    parser.add_argument("--self-test", action="store_true", help="Run local two-node self test")
    parser.add_argument("--daemon", action="store_true", help="Keep node running and log JSON events")
    args = parser.parse_args()

    if args.self_test:
        node_a = AdvanceTetherNode(name="py-alpha", port=0, network_key=args.key)
        node_b = AdvanceTetherNode(name="py-beta", port=0, network_key=args.key)
        node_a.start()
        node_b.start()
        remote_id = node_b.connect("127.0.0.1", node_a.port)
        assert remote_id == node_a.peer_id, "Handshake failed"
        node_b.send_message(node_a.peer_id, "Hello from Python self-test!", rpc="echo")
        node_b.dht_put("greeting", " Peer-to-Peer for all ")
        time.sleep(0.2)
        assert len(node_a.received_messages) >= 1
        assert node_a.dht.get("greeting") == " Peer-to-Peer for all "
        node_a.stop()
        node_b.stop()
        print(json.dumps({"status": "ok", "lang": "python", "peer_a": node_a.peer_id, "peer_b": node_b.peer_id}))
        return 0

    node = AdvanceTetherNode(name=args.name, host=args.host, port=args.port, network_key=args.key)
    node.on("message", lambda m: print(json.dumps({"event": "message", "node": node.peer_id, "data": m}), flush=True))
    node.on("peer_connected", lambda p: print(json.dumps({"event": "peer_connected", "node": node.peer_id, "peer": p["peer_id"], "lang": p["lang"]}), flush=True))
    node.on("dht_put", lambda r: print(json.dumps({"event": "dht_put", "node": node.peer_id, "record": r}), flush=True))
    node.on("pubsub_message", lambda e: print(json.dumps({"event": "pubsub", "node": node.peer_id, "data": e}), flush=True))
    node.on("file_complete", lambda f: print(json.dumps({"event": "file_complete", "node": node.peer_id, "file": f}), flush=True))
    node.on("tunnel_data", lambda t: print(json.dumps({"event": "tunnel_data", "node": node.peer_id, "tunnel_id": t["tunnel_id"], "size": len(t["data"])}), flush=True))

    node.subscribe("global")
    host, port = node.start()
    print(json.dumps({"event": "listening", "peer_id": node.peer_id, "name": node.name, "lang": "python", "host": host, "port": port}), flush=True)

    remote_id = None
    if args.connect:
        c_host, c_port = args.connect.rsplit(":", 1)
        remote_id = node.connect(c_host, int(c_port))

    if args.send and remote_id:
        node.send_message(remote_id, args.send, rpc="echo")
        time.sleep(0.15)

    if args.dht_put and "=" in args.dht_put:
        k, v = args.dht_put.split("=", 1)
        node.dht_put(k, v)
        time.sleep(0.1)

    if args.pub and ":" in args.pub:
        topic, msg = args.pub.split(":", 1)
        node.publish(topic, msg)
        time.sleep(0.1)

    if args.daemon:
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

    node.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
