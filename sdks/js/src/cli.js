#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const assert = require("assert");
const {
  PacketType,
  generatePeerId,
  signEnvelope,
  encodeFrame,
  decodeFrame,
  xorDistance,
  AdvanceTetherNode,
} = require("./index");

async function runSelfTest() {
  const vectorsPath = path.resolve(__dirname, "../../../spec/test_vectors.json");
  if (fs.existsSync(vectorsPath)) {
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
    assert.strictEqual(generatePeerId(vectors.peer_a_seed), vectors.peer_a_id);
    assert.strictEqual(generatePeerId(vectors.peer_b_seed), vectors.peer_b_id);
    assert.strictEqual(xorDistance(vectors.peer_a_id, vectors.peer_b_id).toString(), vectors.xor_distance_u64);
    assert.strictEqual(signEnvelope(vectors.envelope, vectors.network_key), vectors.expected_sig);

    const encFrame = encodeFrame(PacketType.MSG, vectors.envelope, {
      encrypt: true,
      networkKey: vectors.network_key,
      nonceHex: vectors.nonce_hex,
    });
    assert.strictEqual(encFrame.toString("hex"), vectors.encrypted_frame_hex);

    const decoded = decodeFrame(encFrame, vectors.network_key);
    assert.strictEqual(decoded.envelope.body.text, "Peer-to-Peer for all.");
  }

  const nodeA = new AdvanceTetherNode({ name: "js-alpha" });
  const nodeB = new AdvanceTetherNode({ name: "js-beta" });
  await nodeA.start();
  await nodeB.start();
  const remoteId = await nodeB.connect("127.0.0.1", nodeA.port);
  assert.strictEqual(remoteId, nodeA.peerId);

  nodeB.sendMessage(nodeA.peerId, "Hello from Node.js self-test!", "echo");
  nodeB.dhtPut("runtime", "nodejs-v22");
  await new Promise((r) => setTimeout(r, 200));

  assert(nodeA.receivedMessages.length >= 1);
  assert.strictEqual(nodeA.dht.get("runtime"), "nodejs-v22");

  await nodeA.stop();
  await nodeB.stop();
  console.log(JSON.stringify({ status: "ok", lang: "javascript", peer_a: nodeA.peerId, peer_b: nodeB.peerId }));
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) {
    await runSelfTest();
    return;
  }

  const getOpt = (flag, def = null) => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : def;
  };

  const name = getOpt("--name", "js-peer");
  const host = getOpt("--host", "127.0.0.1");
  const port = Number(getOpt("--port", "0"));
  const key = getOpt("--key", "advancetether-default-key");
  const connectTarget = getOpt("--connect");
  const sendText = getOpt("--send");
  const dhtPutArg = getOpt("--dht-put");
  const pubArg = getOpt("--pub");
  const daemon = args.includes("--daemon");

  const node = new AdvanceTetherNode({ name, host, port, networkKey: key });
  node.on("message", (m) => console.log(JSON.stringify({ event: "message", node: node.peerId, data: m })));
  node.on("peer_connected", (p) =>
    console.log(JSON.stringify({ event: "peer_connected", node: node.peerId, peer: p.peer_id, lang: p.lang }))
  );
  node.on("dht_put", (r) => console.log(JSON.stringify({ event: "dht_put", node: node.peerId, record: r })));
  node.on("pubsub_message", (e) => console.log(JSON.stringify({ event: "pubsub", node: node.peerId, data: e })));
  node.on("file_complete", (f) => console.log(JSON.stringify({ event: "file_complete", node: node.peerId, file: f })));
  node.on("tunnel_data", (t) =>
    console.log(JSON.stringify({ event: "tunnel_data", node: node.peerId, tunnel_id: t.tunnel_id, size: t.data.length }))
  );

  const info = await node.start();
  console.log(
    JSON.stringify({
      event: "listening",
      peer_id: node.peerId,
      name: node.name,
      lang: "javascript",
      host: info.host,
      port: info.port,
    })
  );

  let remoteId = null;
  if (connectTarget) {
    const [cHost, cPort] = connectTarget.split(":");
    remoteId = await node.connect(cHost, Number(cPort));
  }

  if (sendText && remoteId) {
    node.sendMessage(remoteId, sendText, "echo");
    await new Promise((r) => setTimeout(r, 150));
  }

  if (dhtPutArg && dhtPutArg.includes("=")) {
    const [k, v] = dhtPutArg.split("=", 2);
    node.dhtPut(k, v);
    await new Promise((r) => setTimeout(r, 100));
  }

  if (pubArg && pubArg.includes(":")) {
    const [topic, msg] = pubArg.split(":", 2);
    node.publish(topic, msg);
    await new Promise((r) => setTimeout(r, 100));
  }

  if (!daemon) {
    await node.stop();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
