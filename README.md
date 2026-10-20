# AdvanceTether (`ATP/1.0`)
**Peer-to-Peer for All Languages.**

AdvanceTether is a full-featured, cross-language Peer-to-Peer (P2P) networking suite and wire protocol (`ATP/1.0`) implemented across **10 programming languages** so that nodes written in any language can discover each other, establish end-to-end encrypted sessions, exchange messages and RPC calls, route a Kademlia XOR Distributed Hash Table (DHT), broadcast topic Pub/Sub events, transfer SHA-256 verified files, and tether/tunnel network streams over TCP, UDP, and WebSockets.

---

## Supported Languages (10 Complete SDKs)

| # | Language | Directory | Key Entrypoint / Module | CLI / Test Command |
|---|----------|-----------|-------------------------|--------------------|
| 1 | **Python** | [`sdks/python/`](sdks/python/) | `advancetether.AdvanceTetherNode` | `PYTHONPATH=sdks/python python3 -m advancetether.cli --self-test` |
| 2 | **JavaScript / TypeScript** | [`sdks/js/`](sdks/js/) | `sdks/js/src/index.js` + `index.d.ts` | `node sdks/js/src/cli.js --self-test` |
| 3 | **C (C11)** | [`sdks/c/`](sdks/c/) | `include/advancetether.h`, `src/advancetether.c` | `make -C sdks/c test` |
| 4 | **C++ (C++17)** | [`sdks/cpp/`](sdks/cpp/) | `include/advancetether.hpp`, `src/advancetether.cpp` | `make -C sdks/cpp test` |
| 5 | **Go** | [`sdks/go/`](sdks/go/) | `advancetether.go`, `cmd/atp-node/main.go` | `cd sdks/go && go run ./cmd/atp-node --self-test` |
| 6 | **Rust** | [`sdks/rust/`](sdks/rust/) | `src/lib.rs`, `src/main.rs` | `cd sdks/rust && cargo run -- --self-test` |
| 7 | **Java** | [`sdks/java/`](sdks/java/) | `io.advancetether.AdvanceTetherNode` | `java io.advancetether.AdvanceTetherNode --self-test` |
| 8 | **C# (.NET)** | [`sdks/csharp/`](sdks/csharp/) | `AdvanceTetherNode.cs`, `Program.cs` | `dotnet run --project sdks/csharp -- --self-test` |
| 9 | **Ruby** | [`sdks/ruby/`](sdks/ruby/) | `lib/advancetether.rb`, `bin/atp-node` | `ruby sdks/ruby/bin/atp-node --self-test` |
| 10| **PHP** | [`sdks/php/`](sdks/php/) | `src/AdvanceTetherNode.php`, `bin/atp-node.php` | `php sdks/php/bin/atp-node.php --self-test` |

---

## Core Architecture & Features

1. **Deterministic Binary Framing (`AT2P` 12-Byte Header)**:
   - `4B` Magic (`"AT2P"` = `0x41543250`) + `1B` Version (`0x01`) + `1B` Flags (`ENCRYPTED`, `COMPRESSED`, `BINARY`, `ACK_REQ`) + `1B` Packet Type (`0x01..0x13`) + `1B` Reserved + `4B` Big-Endian Payload Length.
   - Formal specification in [`spec/ATP-1.0.md`](spec/ATP-1.0.md) and byte-exact cross-language test vectors in [`spec/test_vectors.json`](spec/test_vectors.json).
2. **Cross-Language End-to-End Authenticated Encryption (`ATP-SHA256-CTR-HMAC`)**:
   - Derives separate 256-bit encryption (`K_enc`) and MAC (`K_mac`) keys via SHA-256, encrypts payloads using a 128-bit random nonce + SHA-256 counter keystream, and authenticates ciphertexts with constant-time `HMAC-SHA256`.
   - Zero external C library dependencies required — every single SDK (including standalone C11 and Rust) implements it natively and interoperates byte-for-byte.
3. **Kademlia 64-Bit XOR Distributed Hash Table (DHT)**:
   - Deterministic `peer_id` (`atp_<16-hex-chars>`) and XOR distance metric `distance(a, b) = u64(a) ^ u64(b)` for peer routing and replicated `DHT_PUT` / `DHT_GET` key-value storage.
4. **Direct Messaging, RPC & Topic Pub/Sub**:
   - Point-to-point encrypted `MSG` frames with RPC request/reply correlation and gossip-forwarded `PUBSUB_PUB` topic channels with message ID deduplication.
5. **Chunked SHA-256 Verified File Transfer (`FILE_OFFER`, `FILE_CHUNK`, `FILE_ACK`)**:
   - Splits arbitrary files into chunks, streams them peer-to-peer, reassembles them on the receiving peer, and verifies the full SHA-256 digest before emitting `FILE_ACK`.
6. **P2P Network Tethering & Port-Forwarding Tunnels (`TUNNEL_OPEN`, `TUNNEL_DATA`, `TUNNEL_CLOSE`)**:
   - Opens bidirectional virtual streams between peers across languages to tether and proxy TCP/HTTP traffic.
7. **Interactive Web Dashboard & Polyglot Live Mesh (`dashboard/`)**:
   - Real-time canvas visualizer of the 10-language mesh & Kademlia XOR ring, live `AT2P` binary header inspector, peer spawner, and one-click cross-language interoperability runner.

---

## Quickstart

### 1. Build Native C/C++ Binaries & Run Cross-Language Interop Tests
```bash
make test
# Or directly:
python3 tests/run_all_tests.py
```

### 2. Launch the Interactive Web Dashboard & Signaling Hub
```bash
npm start
# Listening on http://0.0.0.0:3000
```

### 3. Unified CLI (`./bin/atp`)
```bash
chmod +x bin/atp
./bin/atp test
./bin/atp node --lang python --name py-peer --port 9001
./bin/atp node --lang cpp --name cpp-peer --connect 127.0.0.1:9001 --send "Hello from C++17!"
```
