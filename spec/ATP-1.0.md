# AdvanceTether Protocol Specification v1.0 (`ATP/1.0`)

**Peer-to-Peer for All Languages**

`ATP/1.0` is a deterministic, cross-language wire protocol designed so that peer nodes implemented in **Python, JavaScript/TypeScript, Go, Rust, C, C++, Java, C#, Ruby, and PHP** can seamlessly discover one another, negotiate end-to-end encrypted channels, exchange messages and RPC calls, route distributed hash table (DHT) records, gossip pub/sub topics, transfer SHA-256 verified files, and tether network connections over TCP, UDP, and WebSockets.

---

## 1. Binary Wire Frame Format (12-Byte Header)

Every `ATP/1.0` packet sent over TCP streams, UDP datagrams, or WebSocket binary frames begins with a fixed **12-byte big-endian binary header**, immediately followed by `payload_length` bytes of payload:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      'A'      |      'T'      |      '2'      |      'P'      |  Magic (0x41543250)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  |     Flags     |  Packet Type  |   Reserved    |  Control Header
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length                         |  uint32 BE (Bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Payload (UTF-8 JSON /                     |
|                   Encrypted Ciphertext Frame)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields

| Offset | Size | Name | Value / Description |
|--------|------|------|---------------------|
| `0..3` | 4 B | `magic` | ASCII `"AT2P"` (`0x41, 0x54, 0x32, 0x50`) |
| `4` | 1 B | `version` | Protocol version: `0x01` |
| `5` | 1 B | `flags` | Bitmask: `0x01` = `ENCRYPTED`, `0x02` = `COMPRESSED`, `0x04` = `BINARY`, `0x08` = `ACK_REQ` |
| `6` | 1 B | `msg_type` | Packet type identifier (`0x01` – `0x13`) |
| `7` | 1 B | `reserved` | Reserved (`0x00`) |
| `8..11`| 4 B | `length` | Big-endian `uint32` payload byte length (max `16,777,216` bytes / 16 MiB) |

---

## 2. Packet Types (`msg_type`)

| Hex | Name | Direction | Purpose |
|-----|------|-----------|---------|
| `0x01` | `HELLO` | Peer -> Peer | Initial handshake carrying `peer_id`, `name`, `lang`, `port`, `pub_key`, `capabilities` |
| `0x02` | `HELLO_ACK` | Peer -> Peer | Handshake acknowledgement with peer info and session confirmation |
| `0x03` | `PING` | Peer <-> Peer | Liveness probe carrying `ping_id` and `timestamp_ms` |
| `0x04` | `PONG` | Peer <-> Peer | Probe response echoing `ping_id` for RTT calculation |
| `0x05` | `DISCOVER` | Peer -> Mesh/UDP | Request known peers from LAN broadcast or bootstrap rendezvous node |
| `0x06` | `PEER_LIST` | Peer -> Peer | List of active peers (`peer_id`, `host`, `port`, `lang`, `name`) |
| `0x07` | `DHT_PUT` | Peer -> Peer | Store `(key, value, ttl, origin)` in the Kademlia XOR DHT |
| `0x08` | `DHT_GET` | Peer -> Peer | Query `key` from the Kademlia XOR DHT |
| `0x09` | `DHT_RES` | Peer -> Peer | Response with `key`, `value`, `found`, and closest `peers` |
| `0x0A` | `MSG` | Peer -> Peer | Direct peer-to-peer message or RPC request/response |
| `0x0B` | `PUBSUB_SUB`| Peer -> Mesh | Subscribe peer to a named topic |
| `0x0C` | `PUBSUB_PUB`| Peer -> Mesh | Publish an event to a topic (gossip forwarded with `msg_id` deduplication) |
| `0x0D` | `FILE_OFFER`| Peer -> Peer | Announce file transfer (`transfer_id`, `filename`, `size`, `sha256`, `total_chunks`) |
| `0x0E` | `FILE_CHUNK`| Peer -> Peer | Deliver chunk (`transfer_id`, `chunk_index`, `data_b64`, `chunk_sha256`) |
| `0x0F` | `FILE_ACK` | Peer -> Peer | Verify completed chunk/file receipt (`transfer_id`, `status`, `verified`) |
| `0x10` | `TUNNEL_OPEN`| Peer -> Peer | Open a P2P network tether / port-forwarding stream (`tunnel_id`, `target_host`, `target_port`) |
| `0x11` | `TUNNEL_DATA`| Peer <-> Peer| Forward tethered stream bytes (`tunnel_id`, `seq`, `data_b64`) |
| `0x12` | `TUNNEL_CLOSE`| Peer <-> Peer| Tear down a P2P tether channel (`tunnel_id`, `reason`) |
| `0x13` | `HOLE_PUNCH`| Peer <-> Peer| Coordinate UDP/TCP NAT traversal hole-punching (`target_peer_id`, `public_endpoint`) |

---

## 3. Envelope JSON Structure

When `flags & 0x01 == 0` (cleartext) or after decryption when `flags & 0x01 == 1` (encrypted), the payload is a UTF-8 JSON object:

```json
{
  "v": 1,
  "id": "msg_9a8f1b2c3d4e5f60",
  "type": "MSG",
  "from": "atp_7f83b1657ff1fc53",
  "to": "atp_3c2e9d14a05b8812",
  "lang": "python",
  "ts": 1792454400000,
  "ttl": 6,
  "body": {
    "text": "Hello from Python to Rust!",
    "rpc": null
  },
  "sig": "8b4e9c0f..."
}
```

---

## 4. Cross-Language Authenticated Encryption (`ATP-SHA256-CTR-HMAC`)

To guarantee 100% deterministic byte-for-byte interoperability across all 10 languages without requiring external C bindings:

1. **Key Derivation**:
   - Given a shared secret / network key `K_raw` (UTF-8 string), derive a 32-byte master key:
     `K_enc = SHA256("ATP_ENC:" + K_raw)`
     `K_mac = SHA256("ATP_MAC:" + K_raw)`
2. **Encryption (`flags |= 0x01`)**:
   - Generate a 16-byte random `nonce` (encoded as 32 lowercase hex characters).
   - Generate keystream blocks `S_i = SHA256(K_enc || nonce_bytes || uint32_be(i))` for block counter `i = 0, 1, 2, ...`
   - XOR plaintext UTF-8 bytes `P` with keystream `S` to produce ciphertext `C`.
   - Compute authentication tag `tag = HMAC_SHA256(K_mac, nonce_bytes || C)` (64 lowercase hex characters).
   - Encrypted payload JSON structure:
     ```json
     {
       "enc": "ATP-SHA256-CTR-HMAC",
       "nonce": "<32-hex>",
       "ciphertext": "<base64-of-C>",
       "tag": "<64-hex>"
     }
     ```
3. **Decryption & Verification**:
   - Recompute `HMAC_SHA256(K_mac, nonce_bytes || C)` in constant time. Reject frame if mismatch.
   - XOR `C` with the identical SHA-256 counter keystream to recover plaintext `P`.

---

## 5. Kademlia DHT & XOR Routing Metric

- Every `peer_id` is formatted as `atp_<16-hex-chars>`, where the 16 hex characters represent the high 64 bits of `SHA256(node_identity)`.
- **XOR Distance**:
  `distance(peerA, peerB) = uint64(peerA.hex) ^ uint64(peerB.hex)`
- Keys stored via `DHT_PUT` are hashed via `key_id = uint64(SHA256(key)[0..8])` and replicated to the `k` closest peers by XOR distance.
