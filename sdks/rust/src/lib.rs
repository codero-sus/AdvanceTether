//! AdvanceTether Rust SDK (`ATP/1.0`)
//! Zero-dependency implementation of the AdvanceTether Peer-to-Peer Protocol.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: &[u8; 4] = b"AT2P";
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 12;
pub const FLAG_ENCRYPTED: u8 = 0x01;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Hello = 0x01,
    HelloAck = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    Discover = 0x05,
    PeerList = 0x06,
    DhtPut = 0x07,
    DhtGet = 0x08,
    DhtRes = 0x09,
    Msg = 0x0A,
    PubSubSub = 0x0B,
    PubSubPub = 0x0C,
    FileOffer = 0x0D,
    FileChunk = 0x0E,
    FileAck = 0x0F,
    TunnelOpen = 0x10,
    TunnelData = 0x11,
    TunnelClose = 0x12,
    HolePunch = 0x13,
}

impl PacketType {
    pub fn name(self) -> &'static str {
        match self {
            PacketType::Hello => "HELLO",
            PacketType::HelloAck => "HELLO_ACK",
            PacketType::Ping => "PING",
            PacketType::Pong => "PONG",
            PacketType::Discover => "DISCOVER",
            PacketType::PeerList => "PEER_LIST",
            PacketType::DhtPut => "DHT_PUT",
            PacketType::DhtGet => "DHT_GET",
            PacketType::DhtRes => "DHT_RES",
            PacketType::Msg => "MSG",
            PacketType::PubSubSub => "PUBSUB_SUB",
            PacketType::PubSubPub => "PUBSUB_PUB",
            PacketType::FileOffer => "FILE_OFFER",
            PacketType::FileChunk => "FILE_CHUNK",
            PacketType::FileAck => "FILE_ACK",
            PacketType::TunnelOpen => "TUNNEL_OPEN",
            PacketType::TunnelData => "TUNNEL_DATA",
            PacketType::TunnelClose => "TUNNEL_CLOSE",
            PacketType::HolePunch => "HOLE_PUNCH",
        }
    }
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&sha256(data))
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

pub fn generate_peer_id(seed: &str) -> String {
    let hex = sha256_hex(seed.as_bytes());
    format!("atp_{}", &hex[..16])
}

pub fn id_to_u64(peer_id: &str) -> u64 {
    let clean = peer_id.strip_prefix("atp_").unwrap_or(peer_id);
    let padded = format!("{:0<16}", clean);
    u64::from_str_radix(&padded[..16], 16).unwrap_or(0)
}

pub fn xor_distance(peer_a: &str, peer_b: &str) -> u64 {
    id_to_u64(peer_a) ^ id_to_u64(peer_b)
}

pub fn derive_keys(network_key: &str) -> ([u8; 32], [u8; 32]) {
    let k_enc = sha256(format!("ATP_ENC:{}", network_key).as_bytes());
    let k_mac = sha256(format!("ATP_MAC:{}", network_key).as_bytes());
    (k_enc, k_mac)
}

pub fn sign_envelope_fields(
    id: &str,
    pkt_type: &str,
    from_peer: &str,
    to_peer: &str,
    ts: i64,
    network_key: &str,
) -> String {
    let (_k_enc, k_mac) = derive_keys(network_key);
    let canonical = format!("{}:{}:{}:{}:{}", id, pkt_type, from_peer, to_peer, ts);
    let mac = hmac_sha256(&k_mac, canonical.as_bytes());
    to_hex(&mac)[..32].to_string()
}

fn keystream_xor(data: &[u8], k_enc: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let blocks = (data.len() + 31) / 32;
    for counter in 0..blocks {
        let mut block_in = Vec::with_capacity(52);
        block_in.extend_from_slice(k_enc);
        block_in.extend_from_slice(nonce);
        block_in.extend_from_slice(&(counter as u32).to_be_bytes());
        let stream = sha256(&block_in);
        let start = counter * 32;
        let end = (start + 32).min(data.len());
        for i in start..end {
            out[i] = data[i] ^ stream[i - start];
        }
    }
    out
}

pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(4 * ((data.len() + 2) / 3));
    let mut i = 0;
    while i < data.len() {
        let a = data[i] as u32;
        let b = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let c = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (a << 16) | (b << 8) | c;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

pub fn encrypt_payload(plaintext: &[u8], network_key: &str, nonce: &[u8; 16]) -> Vec<u8> {
    let (k_enc, k_mac) = derive_keys(network_key);
    let ciphertext = keystream_xor(plaintext, &k_enc, nonce);
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(&ciphertext);
    let tag = to_hex(&hmac_sha256(&k_mac, &mac_input));
    let nonce_hex = to_hex(nonce);
    let ct_b64 = base64_encode(&ciphertext);
    format!(
        "{{\"enc\":\"ATP-SHA256-CTR-HMAC\",\"nonce\":\"{}\",\"ciphertext\":\"{}\",\"tag\":\"{}\"}}",
        nonce_hex, ct_b64, tag
    )
    .into_bytes()
}

pub fn encode_frame(
    msg_type: PacketType,
    envelope_json: &str,
    encrypt: bool,
    network_key: &str,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut flags = 0u8;
    let payload = if encrypt {
        flags |= FLAG_ENCRYPTED;
        encrypt_payload(envelope_json.as_bytes(), network_key, nonce)
    } else {
        envelope_json.as_bytes().to_vec()
    };
    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.push(VERSION);
    frame.push(flags);
    frame.push(msg_type as u8);
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

pub struct AdvanceTetherNode {
    pub name: String,
    pub peer_id: String,
    pub network_key: String,
    pub dht: HashMap<String, String>,
}

impl AdvanceTetherNode {
    pub fn new(name: &str, network_key: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let peer_id = generate_peer_id(&format!("rust:{}:{}", name, now));
        Self {
            name: name.to_string(),
            peer_id,
            network_key: network_key.to_string(),
            dht: HashMap::new(),
        }
    }

    pub fn bind_listener(&self, host: &str, port: u16) -> std::io::Result<(TcpListener, u16)> {
        let listener = TcpListener::bind((host, port))?;
        let bound_port = listener.local_addr()?.port();
        Ok((listener, bound_port))
    }

    pub fn send_frame(&self, stream: &mut TcpStream, msg_type: PacketType, envelope_json: &str) -> std::io::Result<()> {
        let nonce = [0x42u8; 16];
        let frame = encode_frame(msg_type, envelope_json, true, &self.network_key, &nonce);
        stream.write_all(&frame)
    }

    pub fn read_raw_frame(&self, stream: &mut TcpStream) -> std::io::Result<(u8, u8, Vec<u8>)> {
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header)?;
        let flags = header[5];
        let msg_type = header[6];
        let len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;
        Ok((msg_type, flags, payload))
    }
}
