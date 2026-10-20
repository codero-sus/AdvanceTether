# frozen_string_literal: true

# AdvanceTether Ruby SDK (ATP/1.0)
# Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer & Network Tunneling.

require "socket"
require "openssl"
require "digest"
require "base64"
require "json"
require "securerandom"

module AdvanceTether
  MAGIC = "AT2P"
  VERSION = 1
  HEADER_SIZE = 12
  FLAG_ENCRYPTED = 0x01

  PKT_HELLO        = 0x01
  PKT_HELLO_ACK    = 0x02
  PKT_PING         = 0x03
  PKT_PONG         = 0x04
  PKT_DISCOVER     = 0x05
  PKT_PEER_LIST    = 0x06
  PKT_DHT_PUT      = 0x07
  PKT_DHT_GET      = 0x08
  PKT_DHT_RES      = 0x09
  PKT_MSG          = 0x0A
  PKT_PUBSUB_SUB   = 0x0B
  PKT_PUBSUB_PUB   = 0x0C
  PKT_FILE_OFFER   = 0x0D
  PKT_FILE_CHUNK   = 0x0E
  PKT_FILE_ACK     = 0x0F
  PKT_TUNNEL_OPEN  = 0x10
  PKT_TUNNEL_DATA  = 0x11
  PKT_TUNNEL_CLOSE = 0x12
  PKT_HOLE_PUNCH   = 0x13

  PACKET_NAMES = {
    0x01 => "HELLO",
    0x02 => "HELLO_ACK",
    0x03 => "PING",
    0x04 => "PONG",
    0x05 => "DISCOVER",
    0x06 => "PEER_LIST",
    0x07 => "DHT_PUT",
    0x08 => "DHT_GET",
    0x09 => "DHT_RES",
    0x0A => "MSG",
    0x0B => "PUBSUB_SUB",
    0x0C => "PUBSUB_PUB",
    0x0D => "FILE_OFFER",
    0x0E => "FILE_CHUNK",
    0x0F => "FILE_ACK",
    0x10 => "TUNNEL_OPEN",
    0x11 => "TUNNEL_DATA",
    0x12 => "TUNNEL_CLOSE",
    0x13 => "HOLE_PUNCH"
  }.freeze

  def self.sha256_bytes(data)
    Digest::SHA256.digest(data)
  end

  def self.sha256_hex(data)
    Digest::SHA256.hexdigest(data)
  end

  def self.generate_peer_id(seed = nil)
    raw = seed || SecureRandom.hex(16)
    "atp_#{sha256_hex(raw)[0, 16]}"
  end

  def self.derive_keys(network_key)
    k_enc = sha256_bytes("ATP_ENC:#{network_key}")
    k_mac = sha256_bytes("ATP_MAC:#{network_key}")
    [k_enc, k_mac]
  end

  def self.id_to_u64(peer_id)
    clean = peer_id.start_with?("atp_") ? peer_id[4..] : peer_id
    clean = clean.ljust(16, "0")[0, 16]
    clean.to_i(16)
  end

  def self.xor_distance(peer_a, peer_b)
    id_to_u64(peer_a) ^ id_to_u64(peer_b)
  end

  def self.keystream_xor(data, k_enc, nonce)
    bytes = data.bytes
    out = Array.new(bytes.length, 0)
    blocks = (bytes.length + 31) / 32
    blocks.times do |counter|
      counter_be = [counter].pack("N")
      stream = sha256_bytes(k_enc + nonce + counter_be).bytes
      start_idx = counter * 32
      end_idx = [start_idx + 32, bytes.length].min
      (start_idx...end_idx).each do |i|
        out[i] = bytes[i] ^ stream[i - start_idx]
      end
    end
    out.pack("C*")
  end

  def self.encrypt_payload(plaintext, network_key, nonce_hex = nil)
    k_enc, k_mac = derive_keys(network_key)
    if nonce_hex
      nonce = [nonce_hex].pack("H*")
    else
      nonce = SecureRandom.random_bytes(16)
      nonce_hex = nonce.unpack1("H*")
    end
    ciphertext = keystream_xor(plaintext, k_enc, nonce)
    tag = OpenSSL::HMAC.hexdigest("SHA256", k_mac, nonce + ciphertext)
    JSON.generate({
      "enc" => "ATP-SHA256-CTR-HMAC",
      "nonce" => nonce_hex,
      "ciphertext" => Base64.strict_encode64(ciphertext),
      "tag" => tag
    })
  end

  def self.decrypt_payload(encrypted_json, network_key)
    k_enc, k_mac = derive_keys(network_key)
    env = JSON.parse(encrypted_json)
    raise "Unsupported encryption scheme" unless env["enc"] == "ATP-SHA256-CTR-HMAC"

    nonce = [env["nonce"]].pack("H*")
    ciphertext = Base64.strict_decode64(env["ciphertext"])
    expected_tag = OpenSSL::HMAC.hexdigest("SHA256", k_mac, nonce + ciphertext)
    raise "ATP HMAC mismatch" unless expected_tag == env["tag"]

    keystream_xor(ciphertext, k_enc, nonce)
  end

  def self.sign_envelope(env, network_key)
    _k_enc, k_mac = derive_keys(network_key)
    canonical = "#{env['id']}:#{env['type']}:#{env['from']}:#{env['to']}:#{env['ts']}"
    OpenSSL::HMAC.hexdigest("SHA256", k_mac, canonical)[0, 32]
  end

  def self.encode_frame(msg_type, envelope_hash, encrypt: true, network_key: "advancetether-default-key", nonce_hex: nil)
    raw_json = JSON.generate(envelope_hash)
    flags = 0
    if encrypt
      flags |= FLAG_ENCRYPTED
      payload = encrypt_payload(raw_json, network_key, nonce_hex)
    else
      payload = raw_json
    end
    header = [MAGIC, VERSION, flags, msg_type, 0, payload.bytesize].pack("a4CCCCN")
    header + payload
  end

  def self.decode_frame(frame_bytes, network_key: "advancetether-default-key")
    magic, version, flags, msg_type, _res, len = frame_bytes[0, HEADER_SIZE].unpack("a4CCCCN")
    raise "Invalid ATP magic" unless magic == MAGIC
    raise "Unsupported version" unless version == VERSION

    payload = frame_bytes[HEADER_SIZE, len]
    payload = decrypt_payload(payload, network_key) if (flags & FLAG_ENCRYPTED) != 0
    [msg_type, flags, JSON.parse(payload)]
  end

  class Node
    attr_reader :name, :peer_id, :network_key, :dht

    def initialize(name: "ruby-peer", network_key: "advancetether-default-key")
      @name = name
      @network_key = network_key
      @peer_id = AdvanceTether.generate_peer_id("ruby:#{name}:#{Time.now.to_f}")
      @dht = {}
    end

    def make_envelope(msg_type, body, to_peer: "*")
      env = {
        "v" => VERSION,
        "id" => "msg_#{SecureRandom.hex(8)}",
        "type" => PACKET_NAMES[msg_type] || "MSG",
        "from" => @peer_id,
        "to" => to_peer,
        "lang" => "ruby",
        "ts" => (Time.now.to_f * 1000).to_i,
        "ttl" => 6,
        "body" => body
      }
      env["sig"] = AdvanceTether.sign_envelope(env, @network_key)
      env
    end
  end
end
