"use strict";

/**
 * AdvanceTether JavaScript/TypeScript SDK (ATP/1.0)
 * Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer & Network Tunneling.
 */

const net = require("net");
const dgram = require("dgram");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { EventEmitter } = require("events");

const MAGIC = Buffer.from("AT2P", "ascii");
const VERSION = 1;
const HEADER_SIZE = 12;
const MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;

const FLAG_ENCRYPTED = 0x01;
const FLAG_COMPRESSED = 0x02;
const FLAG_BINARY = 0x04;
const FLAG_ACK_REQ = 0x08;

const PacketType = {
  HELLO: 0x01,
  HELLO_ACK: 0x02,
  PING: 0x03,
  PONG: 0x04,
  DISCOVER: 0x05,
  PEER_LIST: 0x06,
  DHT_PUT: 0x07,
  DHT_GET: 0x08,
  DHT_RES: 0x09,
  MSG: 0x0a,
  PUBSUB_SUB: 0x0b,
  PUBSUB_PUB: 0x0c,
  FILE_OFFER: 0x0d,
  FILE_CHUNK: 0x0e,
  FILE_ACK: 0x0f,
  TUNNEL_OPEN: 0x10,
  TUNNEL_DATA: 0x11,
  TUNNEL_CLOSE: 0x12,
  HOLE_PUNCH: 0x13,
  NAMES: {
    0x01: "HELLO",
    0x02: "HELLO_ACK",
    0x03: "PING",
    0x04: "PONG",
    0x05: "DISCOVER",
    0x06: "PEER_LIST",
    0x07: "DHT_PUT",
    0x08: "DHT_GET",
    0x09: "DHT_RES",
    0x0a: "MSG",
    0x0b: "PUBSUB_SUB",
    0x0c: "PUBSUB_PUB",
    0x0d: "FILE_OFFER",
    0x0e: "FILE_CHUNK",
    0x0f: "FILE_ACK",
    0x10: "TUNNEL_OPEN",
    0x11: "TUNNEL_DATA",
    0x12: "TUNNEL_CLOSE",
    0x13: "HOLE_PUNCH",
  },
};

function sha256Bytes(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function generatePeerId(seed) {
  const raw = Buffer.from(seed || crypto.randomBytes(16).toString("hex"), "utf8");
  return "atp_" + sha256Hex(raw).slice(0, 16);
}

function deriveKeys(networkKey) {
  const kEnc = sha256Bytes(Buffer.from("ATP_ENC:" + networkKey, "utf8"));
  const kMac = sha256Bytes(Buffer.from("ATP_MAC:" + networkKey, "utf8"));
  return { kEnc, kMac };
}

function keystreamXor(dataBuf, kEnc, nonceBuf) {
  const out = Buffer.allocUnsafe(dataBuf.length);
  const blocks = Math.ceil(dataBuf.length / 32);
  const counterBuf = Buffer.alloc(4);
  for (let counter = 0; counter < blocks; counter++) {
    counterBuf.writeUInt32BE(counter, 0);
    const block = sha256Bytes(Buffer.concat([kEnc, nonceBuf, counterBuf]));
    const start = counter * 32;
    const end = Math.min(start + 32, dataBuf.length);
    for (let i = start; i < end; i++) {
      out[i] = dataBuf[i] ^ block[i - start];
    }
  }
  return out;
}

function encryptPayload(plaintextBuf, networkKey, nonceHex = null) {
  const { kEnc, kMac } = deriveKeys(networkKey);
  const nonceBuf = nonceHex ? Buffer.from(nonceHex, "hex") : crypto.randomBytes(16);
  const actualNonceHex = nonceBuf.toString("hex");
  const ciphertext = keystreamXor(plaintextBuf, kEnc, nonceBuf);
  const tag = crypto
    .createHmac("sha256", kMac)
    .update(Buffer.concat([nonceBuf, ciphertext]))
    .digest("hex");
  const env = {
    enc: "ATP-SHA256-CTR-HMAC",
    nonce: actualNonceHex,
    ciphertext: ciphertext.toString("base64"),
    tag,
  };
  return Buffer.from(JSON.stringify(env), "utf8");
}

function decryptPayload(encryptedJsonBuf, networkKey) {
  const { kEnc, kMac } = deriveKeys(networkKey);
  const env = JSON.parse(encryptedJsonBuf.toString("utf8"));
  if (env.enc !== "ATP-SHA256-CTR-HMAC") {
    throw new Error(`Unsupported encryption scheme: ${env.enc}`);
  }
  const nonceBuf = Buffer.from(env.nonce, "hex");
  const ciphertext = Buffer.from(env.ciphertext, "base64");
  const expectedTag = crypto
    .createHmac("sha256", kMac)
    .update(Buffer.concat([nonceBuf, ciphertext]))
    .digest("hex");
  if (
    expectedTag.length !== (env.tag || "").length ||
    !crypto.timingSafeEqual(Buffer.from(expectedTag, "utf8"), Buffer.from(env.tag, "utf8"))
  ) {
    throw new Error("ATP HMAC authentication tag mismatch");
  }
  return keystreamXor(ciphertext, kEnc, nonceBuf);
}

function signEnvelope(envelope, networkKey) {
  const { kMac } = deriveKeys(networkKey);
  const canonical = `${envelope.id || ""}:${envelope.type || ""}:${envelope.from || ""}:${envelope.to || ""}:${envelope.ts || 0}`;
  return crypto.createHmac("sha256", kMac).update(canonical, "utf8").digest("hex").slice(0, 32);
}

function verifyEnvelope(envelope, networkKey) {
  if (!envelope || !envelope.sig) return false;
  const expected = signEnvelope(envelope, networkKey);
  if (expected.length !== envelope.sig.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected, "utf8"), Buffer.from(envelope.sig, "utf8"));
}

function makeEnvelope(msgType, fromPeer, body, options = {}) {
  const toPeer = options.toPeer || "*";
  const lang = options.lang || "javascript";
  const ttl = options.ttl !== undefined ? options.ttl : 6;
  const networkKey = options.networkKey || "advancetether-default-key";
  const env = {
    v: VERSION,
    id: options.msgId || `msg_${crypto.randomBytes(8).toString("hex")}`,
    type: PacketType.NAMES[msgType] || "MSG",
    from: fromPeer,
    to: toPeer,
    lang,
    ts: options.ts !== undefined ? options.ts : Date.now(),
    ttl,
    body,
  };
  env.sig = signEnvelope(env, networkKey);
  return env;
}

function encodeFrame(msgType, envelope, options = {}) {
  const encrypt = Boolean(options.encrypt);
  const networkKey = options.networkKey || "advancetether-default-key";
  let flags = options.flags || 0;
  const rawJson = Buffer.from(JSON.stringify(envelope), "utf8");
  let payload = rawJson;
  if (encrypt) {
    flags |= FLAG_ENCRYPTED;
    payload = encryptPayload(rawJson, networkKey, options.nonceHex || null);
  }
  const header = Buffer.allocUnsafe(HEADER_SIZE);
  MAGIC.copy(header, 0);
  header.writeUInt8(VERSION, 4);
  header.writeUInt8(flags, 5);
  header.writeUInt8(msgType, 6);
  header.writeUInt8(0, 7);
  header.writeUInt32BE(payload.length, 8);
  return Buffer.concat([header, payload]);
}

function decodeFrameHeader(headerBuf) {
  if (headerBuf.length < HEADER_SIZE) {
    throw new Error("Header buffer too short");
  }
  if (!headerBuf.subarray(0, 4).equals(MAGIC)) {
    throw new Error("Invalid ATP magic header");
  }
  const version = headerBuf.readUInt8(4);
  const flags = headerBuf.readUInt8(5);
  const msgType = headerBuf.readUInt8(6);
  const length = headerBuf.readUInt32BE(8);
  if (version !== VERSION) {
    throw new Error(`Unsupported ATP version: ${version}`);
  }
  if (length > MAX_PAYLOAD_SIZE) {
    throw new Error(`Payload exceeds maximum: ${length}`);
  }
  return { version, flags, msgType, length };
}

function decodeFrame(frameBuf, networkKey = "advancetether-default-key") {
  const { flags, msgType, length } = decodeFrameHeader(frameBuf.subarray(0, HEADER_SIZE));
  let payload = frameBuf.subarray(HEADER_SIZE, HEADER_SIZE + length);
  if (flags & FLAG_ENCRYPTED) {
    payload = decryptPayload(payload, networkKey);
  }
  const envelope = JSON.parse(payload.toString("utf8"));
  return { msgType, flags, envelope };
}

function idToBigInt(peerId) {
  const clean = (peerId.startsWith("atp_") ? peerId.slice(4) : peerId).padEnd(16, "0").slice(0, 16);
  if (/^[0-9a-fA-F]{16}$/.test(clean)) {
    return BigInt("0x" + clean);
  }
  const digest = sha256Hex(Buffer.from(peerId, "utf8")).slice(0, 16);
  return BigInt("0x" + digest);
}

function keyToBigInt(key) {
  const digest = sha256Hex(Buffer.from(String(key), "utf8")).slice(0, 16);
  return BigInt("0x" + digest);
}

function xorDistance(idA, idB) {
  return idToBigInt(idA) ^ idToBigInt(idB);
}

class DHTNode {
  constructor(selfPeerId, kBucketSize = 20) {
    this.selfPeerId = selfPeerId;
    this.kBucketSize = kBucketSize;
    this.store = new Map();
    this.routingTable = new Map();
  }

  updatePeer(peerId, host, port, lang = "unknown", name = "") {
    if (!peerId || peerId === this.selfPeerId) return;
    const dist = xorDistance(this.selfPeerId, peerId);
    this.routingTable.set(peerId, {
      peer_id: peerId,
      host,
      port: Number(port),
      lang,
      name: name || peerId,
      xor_distance: dist.toString(),
      last_seen: Date.now(),
    });
  }

  put(key, value, origin = "", ttlSec = 3600) {
    const record = {
      key: String(key),
      key_hash: keyToBigInt(key).toString(16).padStart(16, "0"),
      value,
      origin: origin || this.selfPeerId,
      stored_at: Date.now(),
      expires_at: Date.now() + ttlSec * 1000,
    };
    this.store.set(String(key), record);
    return record;
  }

  get(key) {
    const rec = this.store.get(String(key));
    if (!rec) return null;
    if (rec.expires_at < Date.now()) {
      this.store.delete(String(key));
      return null;
    }
    return rec.value;
  }

  closestPeers(targetKeyOrId, count = 8) {
    const targetInt = String(targetKeyOrId).startsWith("atp_")
      ? idToBigInt(targetKeyOrId)
      : keyToBigInt(targetKeyOrId);
    const peers = Array.from(this.routingTable.values());
    peers.sort((a, b) => {
      const da = idToBigInt(a.peer_id) ^ targetInt;
      const db = idToBigInt(b.peer_id) ^ targetInt;
      return da < db ? -1 : da > db ? 1 : 0;
    });
    return peers.slice(0, count);
  }
}

class AdvanceTetherNode extends EventEmitter {
  constructor(options = {}) {
    super();
    this.name = options.name || "js-node";
    this.lang = options.lang || "javascript";
    this.host = options.host || "127.0.0.1";
    this.port = options.port || 0;
    this.udpPort = options.udpPort || 0;
    this.networkKey = options.networkKey || "advancetether-default-key";
    this.peerId = options.peerId || generatePeerId(`${this.lang}:${this.name}:${Date.now()}:${Math.random()}`);
    this.encrypt = options.encrypt !== undefined ? options.encrypt : true;
    this.downloadDir = options.downloadDir || "/tmp/advancetether_downloads";
    fs.mkdirSync(this.downloadDir, { recursive: true });

    this.dht = new DHTNode(this.peerId);
    this.peers = new Map();
    this.seenMsgIds = new Set();
    this.subscriptions = new Set(["global"]);
    this.incomingFiles = new Map();
    this.completedFiles = new Map();
    this.tunnels = new Map();
    this.receivedMessages = [];
    this.pubsubMessages = [];
    this.stats = {
      frames_sent: 0,
      frames_received: 0,
      bytes_sent: 0,
      bytes_received: 0,
    };
    this.server = null;
    this.udpSocket = null;
    this.running = false;
  }

  async start() {
    if (this.running) return { host: this.host, port: this.port };
    this.running = true;

    await new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this._attachSocket(socket, false));
      this.server.on("error", reject);
      this.server.listen(this.port, this.host, () => {
        const addr = this.server.address();
        this.port = addr.port;
        resolve();
      });
    });

    await new Promise((resolve) => {
      this.udpSocket = dgram.createSocket("udp4");
      this.udpSocket.on("message", (msg, rinfo) => {
        try {
          const { msgType, envelope } = decodeFrame(msg, this.networkKey);
          this._handleEnvelope(msgType, envelope, null, rinfo.address, rinfo.port, true);
        } catch (_e) {}
      });
      this.udpSocket.bind(this.udpPort, this.host, () => {
        try {
          this.udpSocket.setBroadcast(true);
        } catch (_e) {}
        this.udpPort = this.udpSocket.address().port;
        resolve();
      });
    });

    return { host: this.host, port: this.port, udpPort: this.udpPort };
  }

  async stop() {
    this.running = false;
    for (const p of this.peers.values()) {
      if (p.socket) {
        p.socket.destroy();
      }
    }
    this.peers.clear();
    if (this.udpSocket) {
      try {
        this.udpSocket.close();
      } catch (_e) {}
    }
    if (this.server) {
      await new Promise((resolve) => this.server.close(resolve));
    }
  }

  connect(host, port, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port: Number(port) });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error("Connection timeout"));
      }, timeoutMs);

      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      socket.once("connect", () => {
        this._attachSocket(socket, true, (remotePeerId) => {
          clearTimeout(timer);
          resolve(remotePeerId);
        });
        const helloEnv = makeEnvelope(
          PacketType.HELLO,
          this.peerId,
          {
            peer_id: this.peerId,
            name: this.name,
            lang: this.lang,
            host: this.host,
            port: this.port,
            udp_port: this.udpPort,
            capabilities: ["msg", "dht", "pubsub", "file", "tunnel", "e2ee"],
          },
          { lang: this.lang, networkKey: this.networkKey }
        );
        this._sendRawFrame(socket, PacketType.HELLO, helloEnv);
      });
    });
  }

  _attachSocket(socket, isInitiator, onHandshakeAck = null) {
    let buf = Buffer.alloc(0);
    let remotePeerId = null;
    let ackResolved = false;

    socket.on("data", (chunk) => {
      this.stats.bytes_received += chunk.length;
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= HEADER_SIZE) {
        let hdr;
        try {
          hdr = decodeFrameHeader(buf.subarray(0, HEADER_SIZE));
        } catch (_e) {
          socket.destroy();
          return;
        }
        const frameLen = HEADER_SIZE + hdr.length;
        if (buf.length < frameLen) break;
        const frameBytes = buf.subarray(0, frameLen);
        buf = buf.subarray(frameLen);

        try {
          const { msgType, envelope } = decodeFrame(frameBytes, this.networkKey);
          this.stats.frames_received += 1;
          if (!verifyEnvelope(envelope, this.networkKey)) continue;
          if (envelope.from && !remotePeerId) {
            remotePeerId = envelope.from;
          }
          this._handleEnvelope(msgType, envelope, socket, socket.remoteAddress || "127.0.0.1", socket.remotePort || 0, false);
          if (isInitiator && !ackResolved && (msgType === PacketType.HELLO_ACK || msgType === PacketType.HELLO)) {
            ackResolved = true;
            if (onHandshakeAck) onHandshakeAck(envelope.from);
          }
        } catch (_err) {}
      }
    });

    socket.on("close", () => {
      if (remotePeerId) {
        const existing = this.peers.get(remotePeerId);
        if (existing && existing.socket === socket) {
          this.peers.delete(remotePeerId);
          this.emit("peer_disconnected", { peer_id: remotePeerId });
        }
      }
    });

    socket.on("error", () => {});
  }

  _sendRawFrame(socket, msgType, envelope) {
    if (!socket || socket.destroyed) return false;
    const frame = encodeFrame(msgType, envelope, {
      encrypt: this.encrypt,
      networkKey: this.networkKey,
    });
    socket.write(frame);
    this.stats.frames_sent += 1;
    this.stats.bytes_sent += frame.length;
    return true;
  }

  _sendToPeer(peerId, msgType, body) {
    const peer = this.peers.get(peerId);
    if (!peer || !peer.socket) return false;
    const env = makeEnvelope(msgType, this.peerId, body, {
      toPeer: peerId,
      lang: this.lang,
      networkKey: this.networkKey,
    });
    return this._sendRawFrame(peer.socket, msgType, env);
  }

  _broadcast(msgType, body, excludePeer = null, msgId = null) {
    const env = makeEnvelope(msgType, this.peerId, body, {
      toPeer: "*",
      lang: this.lang,
      networkKey: this.networkKey,
      msgId,
    });
    this.seenMsgIds.add(env.id);
    let sent = 0;
    for (const peer of this.peers.values()) {
      if (peer.peer_id === excludePeer) continue;
      if (this._sendRawFrame(peer.socket, msgType, env)) sent++;
    }
    return sent;
  }

  _handleEnvelope(msgType, env, socket, host, port, isUdp) {
    const msgId = env.id || "";
    const senderId = env.from || "";
    const body = env.body || {};

    if (msgType === PacketType.HELLO || msgType === PacketType.HELLO_ACK) {
      const remotePort = Number(body.port || port);
      const remoteLang = body.lang || env.lang || "unknown";
      const remoteName = body.name || senderId;
      if (socket && senderId) {
        const peerInfo = {
          peer_id: senderId,
          socket,
          host,
          port: remotePort,
          lang: remoteLang,
          name: remoteName,
          rtt_ms: 1.0,
        };
        this.peers.set(senderId, peerInfo);
        this.dht.updatePeer(senderId, host, remotePort, remoteLang, remoteName);
        this.emit("peer_connected", peerInfo);

        if (msgType === PacketType.HELLO) {
          const ack = makeEnvelope(
            PacketType.HELLO_ACK,
            this.peerId,
            {
              peer_id: this.peerId,
              name: this.name,
              lang: this.lang,
              host: this.host,
              port: this.port,
              udp_port: this.udpPort,
              peers: this.dht.closestPeers(senderId, 10),
            },
            { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
          );
          this._sendRawFrame(socket, PacketType.HELLO_ACK, ack);
        }
      }
    } else if (msgType === PacketType.PING) {
      if (socket) {
        const pong = makeEnvelope(
          PacketType.PONG,
          this.peerId,
          { ping_id: body.ping_id, sent_ts: body.sent_ts || 0 },
          { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
        );
        this._sendRawFrame(socket, PacketType.PONG, pong);
      }
    } else if (msgType === PacketType.PONG) {
      const sentTs = Number(body.sent_ts || 0);
      if (sentTs && this.peers.has(senderId)) {
        const rtt = Math.max(0.1, Date.now() - sentTs);
        this.peers.get(senderId).rtt_ms = Number(rtt.toFixed(2));
        this.emit("pong", { from: senderId, rtt_ms: rtt });
      }
    } else if (msgType === PacketType.DISCOVER) {
      const peerList = Array.from(this.dht.routingTable.values());
      const resp = makeEnvelope(
        PacketType.PEER_LIST,
        this.peerId,
        { peer_id: this.peerId, name: this.name, lang: this.lang, host: this.host, port: this.port, peers: peerList },
        { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
      );
      if (isUdp && this.udpSocket) {
        const frame = encodeFrame(PacketType.PEER_LIST, resp, { encrypt: this.encrypt, networkKey: this.networkKey });
        this.udpSocket.send(frame, port, host);
      } else if (socket) {
        this._sendRawFrame(socket, PacketType.PEER_LIST, resp);
      }
    } else if (msgType === PacketType.DHT_PUT) {
      if (body.key !== undefined) {
        const rec = this.dht.put(body.key, body.value, senderId);
        this.emit("dht_put", rec);
        if (socket) {
          const ack = makeEnvelope(
            PacketType.DHT_RES,
            this.peerId,
            { key: body.key, value: body.value, found: true, stored: true },
            { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
          );
          this._sendRawFrame(socket, PacketType.DHT_RES, ack);
        }
      }
    } else if (msgType === PacketType.DHT_GET) {
      const val = this.dht.get(body.key);
      if (socket) {
        const resEnv = makeEnvelope(
          PacketType.DHT_RES,
          this.peerId,
          {
            key: body.key,
            value: val,
            found: val !== null,
            peers: this.dht.closestPeers(String(body.key), 6),
          },
          { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
        );
        this._sendRawFrame(socket, PacketType.DHT_RES, resEnv);
      }
    } else if (msgType === PacketType.DHT_RES) {
      if (body.found && body.key) {
        this.dht.put(body.key, body.value, senderId);
      }
      this.emit("dht_res", body);
    } else if (msgType === PacketType.MSG) {
      if (this.seenMsgIds.has(msgId)) return;
      this.seenMsgIds.add(msgId);
      const record = {
        id: msgId,
        from: senderId,
        to: env.to,
        lang: env.lang,
        ts: env.ts,
        body,
      };
      this.receivedMessages.push(record);
      this.emit("message", record);

      if (body.rpc === "echo" && socket) {
        const reply = makeEnvelope(
          PacketType.MSG,
          this.peerId,
          { text: `Echo from ${this.name} (${this.lang}): ${body.text || ""}`, rpc_reply: msgId },
          { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
        );
        this._sendRawFrame(socket, PacketType.MSG, reply);
      }
    } else if (msgType === PacketType.PUBSUB_PUB) {
      if (this.seenMsgIds.has(msgId)) return;
      this.seenMsgIds.add(msgId);
      const topic = body.topic || "general";
      const evt = {
        id: msgId,
        from: senderId,
        lang: env.lang,
        topic,
        data: body.data,
        ts: env.ts,
      };
      if (this.subscriptions.has(topic) || this.subscriptions.has("*")) {
        this.pubsubMessages.push(evt);
        this.emit("pubsub_message", evt);
      }
      if ((env.ttl || 1) > 1) {
        this._broadcast(PacketType.PUBSUB_PUB, body, senderId, msgId);
      }
    } else if (msgType === PacketType.FILE_OFFER) {
      const tid = body.transfer_id;
      this.incomingFiles.set(tid, {
        transfer_id: tid,
        filename: path.basename(body.filename || `${tid}.bin`),
        size: Number(body.size || 0),
        sha256: body.sha256 || "",
        total_chunks: Number(body.total_chunks || 1),
        chunks: new Map(),
        from: senderId,
      });
      this.emit("file_offer", this.incomingFiles.get(tid));
    } else if (msgType === PacketType.FILE_CHUNK) {
      const tid = body.transfer_id;
      const info = this.incomingFiles.get(tid);
      if (info) {
        const idx = Number(body.chunk_index || 0);
        info.chunks.set(idx, Buffer.from(body.data_b64 || "", "base64"));
        if (info.chunks.size >= info.total_chunks) {
          this._finalizeFile(tid, senderId, socket);
        }
      }
    } else if (msgType === PacketType.FILE_ACK) {
      this.emit("file_ack", body);
    } else if (msgType === PacketType.TUNNEL_OPEN) {
      const tid = body.tunnel_id;
      const tun = {
        tunnel_id: tid,
        peer_id: senderId,
        target_host: body.target_host || "127.0.0.1",
        target_port: Number(body.target_port || 0),
        received_bytes: Buffer.alloc(0),
        status: "OPEN",
      };
      this.tunnels.set(tid, tun);
      this.emit("tunnel_open", tun);
    } else if (msgType === PacketType.TUNNEL_DATA) {
      const tid = body.tunnel_id;
      const raw = Buffer.from(body.data_b64 || "", "base64");
      let tun = this.tunnels.get(tid);
      if (!tun) {
        tun = { tunnel_id: tid, peer_id: senderId, received_bytes: Buffer.alloc(0), status: "OPEN" };
        this.tunnels.set(tid, tun);
      }
      tun.received_bytes = Buffer.concat([tun.received_bytes, raw]);
      this.emit("tunnel_data", { tunnel_id: tid, from: senderId, data: raw });
      if (body.echo && socket) {
        const ackEnv = makeEnvelope(
          PacketType.TUNNEL_DATA,
          this.peerId,
          {
            tunnel_id: tid,
            seq: Number(body.seq || 0) + 1,
            data_b64: Buffer.concat([Buffer.from("TETHER_ACK:"), raw]).toString("base64"),
            echo: false,
          },
          { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
        );
        this._sendRawFrame(socket, PacketType.TUNNEL_DATA, ackEnv);
      }
    } else if (msgType === PacketType.TUNNEL_CLOSE) {
      const tid = body.tunnel_id;
      if (this.tunnels.has(tid)) {
        this.tunnels.get(tid).status = "CLOSED";
      }
      this.emit("tunnel_close", body);
    }
  }

  _finalizeFile(tid, senderId, socket) {
    const info = this.incomingFiles.get(tid);
    if (!info) return;
    const ordered = [];
    for (let i = 0; i < info.total_chunks; i++) {
      ordered.push(info.chunks.get(i) || Buffer.alloc(0));
    }
    const fullBuf = Buffer.concat(ordered);
    const actualHash = sha256Hex(fullBuf);
    const verified = info.sha256 ? actualHash === info.sha256 : true;
    const destPath = path.join(this.downloadDir, info.filename);
    fs.writeFileSync(destPath, fullBuf);
    const result = {
      transfer_id: tid,
      filename: info.filename,
      path: destPath,
      size: fullBuf.length,
      sha256: actualHash,
      verified,
      from: senderId,
    };
    this.completedFiles.set(tid, result);
    this.emit("file_complete", result);
    if (socket) {
      const ack = makeEnvelope(
        PacketType.FILE_ACK,
        this.peerId,
        { transfer_id: tid, filename: info.filename, sha256: actualHash, verified },
        { toPeer: senderId, lang: this.lang, networkKey: this.networkKey }
      );
      this._sendRawFrame(socket, PacketType.FILE_ACK, ack);
    }
  }

  sendMessage(peerId, text, rpc = null, extra = {}) {
    const body = { text, ...extra };
    if (rpc) body.rpc = rpc;
    return this._sendToPeer(peerId, PacketType.MSG, body);
  }

  ping(peerId) {
    return this._sendToPeer(peerId, PacketType.PING, {
      ping_id: `ping_${crypto.randomBytes(4).toString("hex")}`,
      sent_ts: Date.now(),
    });
  }

  dhtPut(key, value) {
    const rec = this.dht.put(key, value, this.peerId);
    this._broadcast(PacketType.DHT_PUT, { key, value });
    return rec;
  }

  dhtGet(key) {
    const local = this.dht.get(key);
    if (local !== null) return local;
    this._broadcast(PacketType.DHT_GET, { key });
    return null;
  }

  subscribe(topic) {
    this.subscriptions.add(topic);
    this._broadcast(PacketType.PUBSUB_SUB, { topic });
  }

  publish(topic, data) {
    const msgId = `pub_${crypto.randomBytes(6).toString("hex")}`;
    const evt = {
      id: msgId,
      from: this.peerId,
      lang: this.lang,
      topic,
      data,
      ts: Date.now(),
    };
    if (this.subscriptions.has(topic) || this.subscriptions.has("*")) {
      this.pubsubMessages.push(evt);
      this.emit("pubsub_message", evt);
    }
    return this._broadcast(PacketType.PUBSUB_PUB, { topic, data }, null, msgId);
  }

  sendFileBytes(peerId, filename, contentBuf, chunkSize = 16384) {
    const tid = `file_${crypto.randomBytes(6).toString("hex")}`;
    const digest = sha256Hex(contentBuf);
    const chunks = [];
    for (let i = 0; i < contentBuf.length; i += chunkSize) {
      chunks.push(contentBuf.subarray(i, i + chunkSize));
    }
    if (chunks.length === 0) chunks.push(Buffer.alloc(0));

    const ok = this._sendToPeer(peerId, PacketType.FILE_OFFER, {
      transfer_id: tid,
      filename,
      size: contentBuf.length,
      sha256: digest,
      total_chunks: chunks.length,
    });
    if (!ok) return null;

    chunks.forEach((ch, idx) => {
      this._sendToPeer(peerId, PacketType.FILE_CHUNK, {
        transfer_id: tid,
        chunk_index: idx,
        data_b64: ch.toString("base64"),
        chunk_sha256: sha256Hex(ch),
      });
    });
    return tid;
  }

  openTunnel(peerId, targetHost = "127.0.0.1", targetPort = 8080) {
    const tid = `tun_${crypto.randomBytes(6).toString("hex")}`;
    this.tunnels.set(tid, {
      tunnel_id: tid,
      peer_id: peerId,
      target_host: targetHost,
      target_port: targetPort,
      received_bytes: Buffer.alloc(0),
      status: "OPEN",
    });
    if (this._sendToPeer(peerId, PacketType.TUNNEL_OPEN, { tunnel_id: tid, target_host: targetHost, target_port: targetPort })) {
      return tid;
    }
    return null;
  }

  sendTunnelData(peerId, tunnelId, dataBuf, echo = true) {
    return this._sendToPeer(peerId, PacketType.TUNNEL_DATA, {
      tunnel_id: tunnelId,
      seq: 1,
      data_b64: Buffer.from(dataBuf).toString("base64"),
      echo,
    });
  }

  closeTunnel(peerId, tunnelId) {
    if (this.tunnels.has(tunnelId)) {
      this.tunnels.get(tunnelId).status = "CLOSED";
    }
    return this._sendToPeer(peerId, PacketType.TUNNEL_CLOSE, {
      tunnel_id: tunnelId,
      reason: "closed_by_peer",
    });
  }
}

module.exports = {
  MAGIC,
  VERSION,
  HEADER_SIZE,
  FLAG_ENCRYPTED,
  PacketType,
  sha256Hex,
  generatePeerId,
  deriveKeys,
  encryptPayload,
  decryptPayload,
  signEnvelope,
  verifyEnvelope,
  makeEnvelope,
  encodeFrame,
  decodeFrameHeader,
  decodeFrame,
  idToBigInt,
  xorDistance,
  DHTNode,
  AdvanceTetherNode,
};
