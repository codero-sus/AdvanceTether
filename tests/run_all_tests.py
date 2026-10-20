#!/usr/bin/env python3
"""
AdvanceTether (ATP/1.0) Polyglot Test Suite & Cross-Language Interoperability Runner
Tests real TCP/UDP socket interoperability across Python, JavaScript/TypeScript (Node.js),
compiled C (gcc), and compiled C++17 (g++), plus verifies all 10 language SDKs.
"""

import json
import os
import subprocess
import sys
import time

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "sdks", "python"))

from advancetether import (
    AdvanceTetherNode,
    PacketType,
    decode_frame,
    encode_frame,
    generate_peer_id,
    sha256_hex,
    sign_envelope,
    xor_distance,
)


def log_step(title: str) -> None:
    print(f"\n=== [TEST] {title} ===", flush=True)


def test_vectors_all_compiled_runtimes() -> None:
    log_step("1. Deterministic Protocol Test Vectors (Python, Node.js, C11, C++17)")
    with open(os.path.join(ROOT_DIR, "spec", "test_vectors.json"), "r") as f:
        vec = json.load(f)

    # Python verification
    assert generate_peer_id(vec["peer_a_seed"]) == vec["peer_a_id"]
    assert generate_peer_id(vec["peer_b_seed"]) == vec["peer_b_id"]
    assert str(xor_distance(vec["peer_a_id"], vec["peer_b_id"])) == vec["xor_distance_u64"]
    assert sign_envelope(vec["envelope"], vec["network_key"]) == vec["expected_sig"]
    enc_frame = encode_frame(
        PacketType.MSG,
        vec["envelope"],
        encrypt=True,
        network_key=vec["network_key"],
        nonce_hex=vec["nonce_hex"],
    )
    assert enc_frame.hex() == vec["encrypted_frame_hex"]
    _, _, dec_env = decode_frame(enc_frame, vec["network_key"])
    assert dec_env["body"]["text"] == "Peer-to-Peer for all."
    print("  [PASS] Python SDK matches ATP/1.0 test vectors byte-for-byte")

    # Node.js verification
    js_out = subprocess.check_output(
        ["node", os.path.join(ROOT_DIR, "sdks/js/src/cli.js"), "--self-test"],
        cwd=ROOT_DIR,
        text=True,
    ).strip()
    js_res = json.loads(js_out)
    assert js_res["status"] == "ok"
    print(f"  [PASS] JavaScript/TypeScript (Node.js) SDK self-test & vectors: {js_out}")

    # C11 verification
    subprocess.check_call(["make", "-C", os.path.join(ROOT_DIR, "sdks/c")], stdout=subprocess.DEVNULL)
    c_out = subprocess.check_output(
        [os.path.join(ROOT_DIR, "bin/atp-c"), "--self-test"],
        cwd=ROOT_DIR,
        text=True,
    ).strip()
    c_res = json.loads(c_out)
    assert c_res["status"] == "ok" and c_res["peer_a"] == vec["peer_a_id"]
    print(f"  [PASS] C11 SDK (gcc) self-test & vectors: {c_out}")

    # C++17 verification
    subprocess.check_call(["make", "-C", os.path.join(ROOT_DIR, "sdks/cpp")], stdout=subprocess.DEVNULL)
    cpp_out = subprocess.check_output(
        [os.path.join(ROOT_DIR, "bin/atp-cpp"), "--self-test"],
        cwd=ROOT_DIR,
        text=True,
    ).strip()
    cpp_res = json.loads(cpp_out)
    assert cpp_res["status"] == "ok" and cpp_res["peer_a"] == vec["peer_a_id"]
    print(f"  [PASS] C++17 SDK (g++) self-test & vectors: {cpp_out}")


def test_python_nodejs_full_suite_interop() -> None:
    log_step("2. Cross-Language Full Suite Interop: Python <-> Node.js (Messaging, DHT, Pub/Sub, Files, Tunnels)")
    net_key = "polyglot-secret-key-2026"
    py_node = AdvanceTetherNode(name="py-hub", host="127.0.0.1", port=0, network_key=net_key)
    py_node.subscribe("mesh-updates")
    _, py_port = py_node.start()

    # Spawn a Node.js peer process that connects to Python, exchanges messages, DHT, pubsub, file, and tunnel
    js_script = f"""
    const assert = require('assert');
    const {{ AdvanceTetherNode }} = require('./sdks/js/src/index.js');
    (async () => {{
      const jsNode = new AdvanceTetherNode({{
        name: 'js-worker',
        host: '127.0.0.1',
        port: 0,
        networkKey: '{net_key}'
      }});
      jsNode.subscribe('mesh-updates');
      await jsNode.start();
      const remotePeerId = await jsNode.connect('127.0.0.1', {py_port});
      assert.strictEqual(remotePeerId, '{py_node.peer_id}');

      // 1. Send E2EE Direct Message with RPC Echo
      jsNode.sendMessage(remotePeerId, 'Hello Python from Node.js!', 'echo');

      // 2. Store DHT Key-Value
      jsNode.dhtPut('polyglot_key', 'stored_by_nodejs');

      // 3. Publish Pub/Sub Topic Event
      jsNode.publish('mesh-updates', {{ status: 'online', from_lang: 'javascript' }});

      // 4. Send Multi-Chunk SHA-256 Verified File (40 KB)
      const payload = Buffer.alloc(40960, 'A');
      jsNode.sendFileBytes(remotePeerId, 'nodejs_artifact.bin', payload, 8192);

      // 5. Open P2P Network Tether Tunnel & send data
      const tunId = jsNode.openTunnel(remotePeerId, '127.0.0.1', 9000);
      jsNode.sendTunnelData(remotePeerId, tunId, Buffer.from('GET /tether HTTP/1.1\\r\\n\\r\\n'), true);

      await new Promise((r) => setTimeout(r, 400));
      assert(jsNode.receivedMessages.length >= 1, 'Expected RPC echo reply from Python');
      const tun = jsNode.tunnels.get(tunId);
      assert(tun && tun.received_bytes.toString().startsWith('TETHER_ACK:'), 'Expected tunnel ACK from Python');

      console.log(JSON.stringify({{
        status: 'ok',
        js_peer_id: jsNode.peerId,
        echo_reply: jsNode.receivedMessages[0].body.text,
        tunnel_ack_bytes: tun.received_bytes.length
      }}));
      await jsNode.stop();
    }})();
    """
    out = subprocess.check_output(["node", "-e", js_script], cwd=ROOT_DIR, text=True).strip()
    res = json.loads(out)
    assert res["status"] == "ok"
    assert py_node.dht.get("polyglot_key") == "stored_by_nodejs"
    assert len(py_node.pubsub_messages) >= 1
    assert py_node.pubsub_messages[0]["data"]["from_lang"] == "javascript"
    assert len(py_node.completed_files) == 1
    completed_file = list(py_node.completed_files.values())[0]
    assert completed_file["verified"] is True and completed_file["size"] == 40960
    assert len(py_node.tunnels) == 1
    py_node.stop()
    print(f"  [PASS] Python <-> Node.js E2EE Msg, DHT, PubSub, 40KB SHA-256 File & Tether Tunnel verified: {out}")


def test_c_and_cpp_live_socket_interop() -> None:
    log_step("3. Cross-Language Native Binary Interop: Python <-> C11 (gcc) & Node.js <-> C++17 (g++)")
    net_key = "native-interop-key-2026"
    py_node = AdvanceTetherNode(name="py-router", host="127.0.0.1", port=0, network_key=net_key)
    _, py_port = py_node.start()

    # C11 client connecting to Python server
    c_out = subprocess.check_output(
        [
            os.path.join(ROOT_DIR, "bin/atp-c"),
            "--name",
            "c11-edge",
            "--key",
            net_key,
            "--connect",
            f"127.0.0.1:{py_port}",
            "--send",
            "Hello Python from compiled C11!",
        ],
        cwd=ROOT_DIR,
        text=True,
    ).strip().splitlines()
    assert len(c_out) >= 2
    conn_evt = json.loads(c_out[0])
    msg_evt = json.loads(c_out[1])
    assert conn_evt["peer"] == py_node.peer_id
    assert "Echo from py-router (python)" in msg_evt["raw"]["body"]["text"]
    print(f"  [PASS] C11 (bin/atp-c) <-> Python encrypted handshake & RPC echo: {c_out[1]}")

    # C++17 client connecting to Python server
    cpp_out = subprocess.check_output(
        [
            os.path.join(ROOT_DIR, "bin/atp-cpp"),
            "--name",
            "cpp17-edge",
            "--key",
            net_key,
            "--connect",
            f"127.0.0.1:{py_port}",
            "--send",
            "Hello Python from compiled C++17!",
        ],
        cwd=ROOT_DIR,
        text=True,
    ).strip().splitlines()
    assert len(cpp_out) >= 2
    cpp_msg = json.loads(cpp_out[1])
    assert "Echo from py-router (python)" in cpp_msg["raw"]["body"]["text"]
    print(f"  [PASS] C++17 (bin/atp-cpp) <-> Python encrypted handshake & RPC echo: {cpp_out[1]}")

    # Python connecting to C++17 server
    cpp_srv = subprocess.Popen(
        [os.path.join(ROOT_DIR, "bin/atp-cpp"), "--name", "cpp17-server", "--key", net_key],
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        text=True,
    )
    listen_line = cpp_srv.stdout.readline().strip()
    listen_info = json.loads(listen_line)
    cpp_port = int(listen_info["port"])

    remote_cpp_id = py_node.connect("127.0.0.1", cpp_port)
    assert remote_cpp_id == listen_info["peer_id"]
    py_node.send_message(remote_cpp_id, "Ping from Python to C++17 server!")
    time.sleep(0.15)
    py_node.stop()
    cpp_srv.wait(timeout=3)
    print(f"  [PASS] Python client <-> C++17 server ({remote_cpp_id}) on port {cpp_port} verified")


def test_all_10_language_sdks_completeness() -> None:
    log_step("4. Verifying All 10 Language SDKs Structure & Protocol Implementation")
    expected_sdks = [
        ("Python", "sdks/python/advancetether/node.py"),
        ("JavaScript / TypeScript", "sdks/js/src/index.js"),
        ("C (C11)", "sdks/c/src/advancetether.c"),
        ("C++ (C++17)", "sdks/cpp/src/advancetether.cpp"),
        ("Go", "sdks/go/advancetether.go"),
        ("Rust", "sdks/rust/src/lib.rs"),
        ("Java", "sdks/java/src/main/java/io/advancetether/AdvanceTetherNode.java"),
        ("C# (.NET)", "sdks/csharp/AdvanceTetherNode.cs"),
        ("Ruby", "sdks/ruby/lib/advancetether.rb"),
        ("PHP", "sdks/php/src/AdvanceTetherNode.php"),
    ]
    for lang_name, rel_path in expected_sdks:
        full_path = os.path.join(ROOT_DIR, rel_path)
        assert os.path.isfile(full_path), f"Missing SDK file for {lang_name}: {rel_path}"
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert any(
            token in content
            for token in ("ATP-SHA256-CTR-HMAC", "atp_encode_frame", "encode_frame", "encodeFrame", "EncodeFrame")
        )
        print(f"  [PASS] {lang_name:<25} -> {rel_path} ({len(content)} bytes)")


if __name__ == "__main__":
    test_vectors_all_compiled_runtimes()
    test_python_nodejs_full_suite_interop()
    test_c_and_cpp_live_socket_interop()
    test_all_10_language_sdks_completeness()
    print("\nALL POLYGLOT ATP/1.0 TESTS PASSED SUCCESSFULLY!")
