"use strict";

let meshState = {
  languages: [],
  peers: [],
  links: [],
  dht: [],
  files: [],
  tunnels: [],
  recentEvents: [],
};
let sdkData = null;
const flyingPackets = [];
const nodePositions = new Map();

const canvas = document.getElementById("mesh-canvas");
const ctx = canvas.getContext("2d");

async function apiGet(url) {
  const res = await fetch(url);
  return res.json();
}

async function apiPost(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

function populateSelects() {
  const spawnLang = document.getElementById("spawn-lang");
  if (spawnLang.options.length === 0 && meshState.languages.length > 0) {
    for (const l of meshState.languages) {
      const opt = document.createElement("option");
      opt.value = l.id;
      opt.textContent = `${l.label} (${l.badge})`;
      spawnLang.appendChild(opt);
    }
  }

  const peerSelects = document.querySelectorAll(".peer-select");
  peerSelects.forEach((sel, idx) => {
    const prev = sel.value;
    sel.innerHTML = "";
    meshState.peers.forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.peer_id;
      opt.textContent = `[${p.badge}] ${p.name} (${p.peer_id.slice(0, 10)}.. :${p.port})`;
      sel.appendChild(opt);
    });
    if (prev && meshState.peers.some((p) => p.peer_id === prev)) {
      sel.value = prev;
    } else if (meshState.peers.length > 1) {
      sel.selectedIndex = idx % 2 === 1 ? 1 : 0;
    }
  });
}

function renderPeersAndLists() {
  document.getElementById("stat-peers").textContent = meshState.peers.length;
  document.getElementById("stat-links").textContent = meshState.links.length;
  document.getElementById("stat-dht").textContent = meshState.dht.length;
  document.getElementById("peer-count-label").textContent = meshState.peers.length;

  const peerListEl = document.getElementById("peer-list");
  peerListEl.innerHTML = "";
  meshState.peers.forEach((p) => {
    const card = document.createElement("div");
    card.className = "peer-card";
    card.innerHTML = `
      <div class="peer-card-top">
        <strong>${p.name}</strong>
        <span class="lang-tag" style="background:${p.color}">${p.badge}</span>
      </div>
      <div class="peer-meta">${p.peer_id}</div>
      <div class="peer-meta">TCP :${p.port} &bull; Peers: ${p.peerCount} &bull; RX: ${p.stats.frames_received}</div>
    `;
    card.addEventListener("click", () => {
      document.getElementById("msg-from").value = p.peer_id;
    });
    peerListEl.appendChild(card);
  });

  const dhtEl = document.getElementById("dht-table");
  dhtEl.innerHTML = "";
  meshState.dht.forEach((rec) => {
    const item = document.createElement("div");
    item.className = "mini-item";
    item.innerHTML = `<strong>${rec.key}</strong> = <code>${JSON.stringify(rec.value)}</code> <span style="color:#64748b">(xor_hash: ${rec.key_hash}, origin: ${rec.origin.slice(0, 12)}..)</span>`;
    dhtEl.appendChild(item);
  });

  const fileEl = document.getElementById("file-list");
  fileEl.innerHTML = "";
  meshState.files.forEach((f) => {
    const item = document.createElement("div");
    item.className = "mini-item";
    item.innerHTML = `<strong>${f.filename}</strong> (${f.size} B) &rarr; ${f.toName} [${f.toLang}] &bull; SHA256: <span style="color:#10b981">${f.sha256.slice(0, 16)}... (verified=${f.verified})</span>`;
    fileEl.appendChild(item);
  });

  const tunEl = document.getElementById("tunnel-list");
  tunEl.innerHTML = "";
  meshState.tunnels.forEach((t) => {
    const item = document.createElement("div");
    item.className = "mini-item";
    item.innerHTML = `<strong>${t.tunnel_id}</strong> [${t.status}] ${t.ownerName} &harr; ${t.target_host}:${t.target_port} (${t.bytes_transferred} bytes tethered)`;
    tunEl.appendChild(item);
  });
}

function addWireEntry(evt, animate = true) {
  const wireLog = document.getElementById("wire-log");
  const div = document.createElement("div");
  div.className = "wire-entry";
  const timeStr = new Date(evt.ts || Date.now()).toLocaleTimeString();
  const hdrLine = evt.headerHex
    ? `<div class="wire-hex">AT2P Header [12B]: ${evt.headerHex} (${evt.frameSize}B frame, E2EE=ATP-SHA256-CTR-HMAC)</div>`
    : "";
  div.innerHTML = `
    <div class="wire-meta">
      <span>[${evt.kind}] ${evt.from ? evt.from.slice(0, 14) : "system"} &rarr; ${evt.to ? evt.to.slice(0, 14) : "mesh"}</span>
      <span>${timeStr}</span>
    </div>
    <div>${evt.summary || ""}</div>
    ${hdrLine}
  `;
  wireLog.prepend(div);
  while (wireLog.children.length > 40) {
    wireLog.removeChild(wireLog.lastChild);
  }

  if (animate && evt.from && evt.to && nodePositions.has(evt.from) && nodePositions.has(evt.to)) {
    flyingPackets.push({
      from: evt.from,
      to: evt.to,
      progress: 0,
      color: evt.kind === "DHT_PUT" ? "#10b981" : evt.kind === "FILE_ACK" ? "#f59e0b" : "#38bdf8",
    });
  }
}

function layoutNodes() {
  const w = canvas.width;
  const h = canvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const rx = Math.min(w, h) * 0.37;
  const ry = Math.min(w, h) * 0.36;
  const n = meshState.peers.length || 1;

  meshState.peers.forEach((p, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
    nodePositions.set(p.peer_id, {
      x: cx + Math.cos(angle) * rx,
      y: cy + Math.sin(angle) * ry,
      peer: p,
    });
  });
}

function drawMesh() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  layoutNodes();

  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const r = Math.min(canvas.width, canvas.height) * 0.365;

  // Draw Kademlia XOR Ring
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(59, 130, 246, 0.14)";
  ctx.setLineDash([5, 6]);
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.restore();

  // Draw Peer TCP Links
  meshState.links.forEach((lnk) => {
    const a = nodePositions.get(lnk.source);
    const b = nodePositions.get(lnk.target);
    if (!a || !b) return;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.strokeStyle = "rgba(148, 163, 184, 0.24)";
    ctx.lineWidth = 1.4;
    ctx.stroke();
  });

  // Draw Flying AT2P Packets
  for (let i = flyingPackets.length - 1; i >= 0; i--) {
    const pkt = flyingPackets[i];
    pkt.progress += 0.035;
    if (pkt.progress >= 1) {
      flyingPackets.splice(i, 1);
      continue;
    }
    const a = nodePositions.get(pkt.from);
    const b = nodePositions.get(pkt.to);
    if (!a || !b) continue;
    const px = a.x + (b.x - a.x) * pkt.progress;
    const py = a.y + (b.y - a.y) * pkt.progress;
    ctx.beginPath();
    ctx.arc(px, py, 5.5, 0, Math.PI * 2);
    ctx.fillStyle = pkt.color;
    ctx.shadowColor = pkt.color;
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  // Draw Peer Nodes
  for (const { x, y, peer } of nodePositions.values()) {
    ctx.beginPath();
    ctx.arc(x, y, 20, 0, Math.PI * 2);
    ctx.fillStyle = "#0f172a";
    ctx.fill();
    ctx.lineWidth = 2.5;
    ctx.strokeStyle = peer.color;
    ctx.stroke();

    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 10px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(peer.badge, x, y);

    ctx.fillStyle = "#cbd5e1";
    ctx.font = "11px sans-serif";
    ctx.fillText(peer.name, x, y + 31);
  }

  requestAnimationFrame(drawMesh);
}

async function refreshState(initial = false) {
  meshState = await apiGet("api/state");
  populateSelects();
  renderPeersAndLists();
  if (initial && meshState.recentEvents) {
    const wireLog = document.getElementById("wire-log");
    wireLog.innerHTML = "";
    meshState.recentEvents.slice().reverse().forEach((e) => addWireEntry(e, false));
  }
}

async function loadSdks() {
  sdkData = await apiGet("api/sdks");
  const sel = document.getElementById("sdk-select");
  sel.innerHTML = "";
  sdkData.sdks.forEach((s, idx) => {
    const opt = document.createElement("option");
    opt.value = idx;
    opt.textContent = `${s.label} — ${s.sdkPath}`;
    sel.appendChild(opt);
  });
  const updateView = () => {
    const chosen = sdkData.sdks[Number(sel.value) || 0];
    document.getElementById("sdk-cli-cmd").textContent = chosen.cliCmd;
    document.getElementById("sdk-code-view").textContent = chosen.code;
  };
  sel.addEventListener("change", updateView);
  updateView();
}

// UI Event Listeners
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

document.getElementById("btn-spawn").addEventListener("click", async () => {
  const lang = document.getElementById("spawn-lang").value;
  const name = document.getElementById("spawn-name").value.trim();
  await apiPost("api/spawn", { lang, name });
  document.getElementById("spawn-name").value = "";
  await refreshState();
});

document.getElementById("btn-send-msg").addEventListener("click", async () => {
  const from = document.getElementById("msg-from").value;
  const to = document.getElementById("msg-to").value;
  const text = document.getElementById("msg-text").value;
  const rpc = document.getElementById("msg-rpc").checked;
  await apiPost("api/message", { from, to, text, rpc });
  setTimeout(refreshState, 200);
});

document.getElementById("btn-dht-put").addEventListener("click", async () => {
  const from = document.getElementById("dht-from").value;
  const key = document.getElementById("dht-key").value;
  const value = document.getElementById("dht-val").value;
  await apiPost("api/dht", { from, key, value });
  await refreshState();
});

document.getElementById("btn-pub").addEventListener("click", async () => {
  const from = document.getElementById("pub-from").value;
  const topic = document.getElementById("pub-topic").value;
  const data = document.getElementById("pub-data").value;
  await apiPost("api/pubsub", { from, topic, data });
  await refreshState();
});

document.getElementById("btn-send-file").addEventListener("click", async () => {
  const from = document.getElementById("file-from").value;
  const to = document.getElementById("file-to").value;
  const filename = document.getElementById("file-name").value;
  const content = document.getElementById("file-content").value;
  await apiPost("api/file", { from, to, filename, content });
  setTimeout(refreshState, 250);
});

document.getElementById("btn-open-tunnel").addEventListener("click", async () => {
  const from = document.getElementById("tun-from").value;
  const to = document.getElementById("tun-to").value;
  const targetHost = document.getElementById("tun-host").value;
  const targetPort = document.getElementById("tun-port").value;
  const payload = document.getElementById("tun-payload").value;
  await apiPost("api/tunnel", { from, to, targetHost, targetPort, payload });
  setTimeout(refreshState, 250);
});

document.getElementById("btn-run-interop").addEventListener("click", async () => {
  const btn = document.getElementById("btn-run-interop");
  btn.textContent = "Running Polyglot Interop Tests...";
  btn.disabled = true;
  try {
    const res = await apiPost("api/interop-test", {});
    addWireEntry({
      kind: res.ok ? "INTEROP_PASS" : "INTEROP_ERR",
      from: "polyglot-runner",
      to: "all-10-sdks",
      summary: res.output.split("\n").slice(-6).join(" | "),
    });
  } finally {
    btn.textContent = "Run 10-Language Interop Suite";
    btn.disabled = false;
  }
});

// Connect SSE stream using relative URL
const evtSource = new EventSource("api/events");
evtSource.onmessage = (e) => {
  try {
    const data = JSON.parse(e.data);
    if (data.kind && data.kind !== "CONNECTED") {
      addWireEntry(data, true);
    }
  } catch (_err) {}
};

refreshState(true);
loadSdks();
requestAnimationFrame(drawMesh);
