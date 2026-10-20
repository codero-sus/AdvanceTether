package io.advancetether;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AdvanceTether Java SDK (ATP/1.0)
 * Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer & Network Tunneling.
 */
public class AdvanceTetherNode {
    public static final byte[] MAGIC = new byte[]{'A', 'T', '2', 'P'};
    public static final byte VERSION = 1;
    public static final int HEADER_SIZE = 12;
    public static final byte FLAG_ENCRYPTED = 0x01;

    public static final byte PKT_HELLO = 0x01;
    public static final byte PKT_HELLO_ACK = 0x02;
    public static final byte PKT_PING = 0x03;
    public static final byte PKT_PONG = 0x04;
    public static final byte PKT_DISCOVER = 0x05;
    public static final byte PKT_PEER_LIST = 0x06;
    public static final byte PKT_DHT_PUT = 0x07;
    public static final byte PKT_DHT_GET = 0x08;
    public static final byte PKT_DHT_RES = 0x09;
    public static final byte PKT_MSG = 0x0A;
    public static final byte PKT_PUBSUB_SUB = 0x0B;
    public static final byte PKT_PUBSUB_PUB = 0x0C;
    public static final byte PKT_FILE_OFFER = 0x0D;
    public static final byte PKT_FILE_CHUNK = 0x0E;
    public static final byte PKT_FILE_ACK = 0x0F;
    public static final byte PKT_TUNNEL_OPEN = 0x10;
    public static final byte PKT_TUNNEL_DATA = 0x11;
    public static final byte PKT_TUNNEL_CLOSE = 0x12;
    public static final byte PKT_HOLE_PUNCH = 0x13;

    private final String name;
    private final String peerId;
    private final String networkKey;
    private final Map<String, String> dhtStore = new ConcurrentHashMap<>();
    private ServerSocket serverSocket;

    public AdvanceTetherNode(String name, String networkKey) {
        this.name = name;
        this.networkKey = networkKey != null ? networkKey : "advancetether-default-key";
        this.peerId = generatePeerId("java:" + name + ":" + System.nanoTime());
    }

    public String getPeerId() {
        return peerId;
    }

    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String generatePeerId(String seed) {
        byte[] digest = sha256(seed.getBytes(StandardCharsets.UTF_8));
        return "atp_" + toHex(digest).substring(0, 16);
    }

    public static BigInteger idToUint64(String peerId) {
        String clean = peerId.startsWith("atp_") ? peerId.substring(4) : peerId;
        if (clean.length() < 16) {
            clean = String.format("%-16s", clean).replace(' ', '0');
        } else if (clean.length() > 16) {
            clean = clean.substring(0, 16);
        }
        return new BigInteger(clean, 16);
    }

    public static BigInteger xorDistance(String peerA, String peerB) {
        return idToUint64(peerA).xor(idToUint64(peerB));
    }

    public static String signEnvelopeFields(String id, String type, String from, String to, long ts, String networkKey) {
        byte[] kMac = sha256(("ATP_MAC:" + networkKey).getBytes(StandardCharsets.UTF_8));
        String canonical = id + ":" + type + ":" + from + ":" + to + ":" + ts;
        byte[] mac = hmacSha256(kMac, canonical.getBytes(StandardCharsets.UTF_8));
        return toHex(mac).substring(0, 32);
    }

    private static byte[] keystreamXor(byte[] data, byte[] kEnc, byte[] nonce) {
        byte[] out = new byte[data.length];
        int blocks = (data.length + 31) / 32;
        for (int counter = 0; counter < blocks; counter++) {
            ByteBuffer buf = ByteBuffer.allocate(52);
            buf.put(kEnc);
            buf.put(nonce);
            buf.putInt(counter);
            byte[] stream = sha256(buf.array());
            int start = counter * 32;
            int end = Math.min(start + 32, data.length);
            for (int i = start; i < end; i++) {
                out[i] = (byte) (data[i] ^ stream[i - start]);
            }
        }
        return out;
    }

    public static byte[] encryptPayload(byte[] plaintext, String networkKey, String nonceHex) {
        byte[] kEnc = sha256(("ATP_ENC:" + networkKey).getBytes(StandardCharsets.UTF_8));
        byte[] kMac = sha256(("ATP_MAC:" + networkKey).getBytes(StandardCharsets.UTF_8));
        byte[] nonce;
        if (nonceHex != null && !nonceHex.isEmpty()) {
            nonce = fromHex(nonceHex);
        } else {
            nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);
            nonceHex = toHex(nonce);
        }
        byte[] ciphertext = keystreamXor(plaintext, kEnc, nonce);
        ByteBuffer macIn = ByteBuffer.allocate(nonce.length + ciphertext.length);
        macIn.put(nonce);
        macIn.put(ciphertext);
        String tag = toHex(hmacSha256(kMac, macIn.array()));
        String b64 = Base64.getEncoder().encodeToString(ciphertext);
        String json = String.format(
                "{\"enc\":\"ATP-SHA256-CTR-HMAC\",\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\"}",
                nonceHex, b64, tag
        );
        return json.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] encodeFrame(byte msgType, String envelopeJson, boolean encrypt, String networkKey, String nonceHex) {
        byte flags = 0;
        byte[] payload = envelopeJson.getBytes(StandardCharsets.UTF_8);
        if (encrypt) {
            flags |= FLAG_ENCRYPTED;
            payload = encryptPayload(payload, networkKey, nonceHex);
        }
        ByteBuffer frame = ByteBuffer.allocate(HEADER_SIZE + payload.length);
        frame.put(MAGIC);
        frame.put(VERSION);
        frame.put(flags);
        frame.put(msgType);
        frame.put((byte) 0);
        frame.putInt(payload.length);
        frame.put(payload);
        return frame.array();
    }

    public int startServer(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        return serverSocket.getLocalPort();
    }

    public void dhtPut(String key, String value) {
        dhtStore.put(key, value);
    }

    public String dhtGet(String key) {
        return dhtStore.get(key);
    }

    public void sendFrame(Socket socket, byte msgType, String envelopeJson) throws IOException {
        byte[] frame = encodeFrame(msgType, envelopeJson, true, networkKey, null);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.write(frame);
        out.flush();
    }

    public byte[] readRawPayload(Socket socket) throws IOException {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] header = new byte[HEADER_SIZE];
        in.readFully(header);
        ByteBuffer hb = ByteBuffer.wrap(header);
        int len = hb.getInt(8);
        byte[] payload = new byte[len];
        in.readFully(payload);
        return payload;
    }

    public static void main(String[] args) throws Exception {
        for (String arg : args) {
            if ("--self-test".equals(arg)) {
                String netKey = "advancetether-universal-key-2026";
                String peerA = generatePeerId("seed-alpha");
                String peerB = generatePeerId("seed-beta");
                BigInteger dist = xorDistance(peerA, peerB);
                String sig = signEnvelopeFields("msg_0123456789abcdef", "MSG", peerA, peerB, 1792454400000L, netKey);
                if (!"atp_ba316cd7abc9b7dc".equals(peerA) || !"278c381e5f2ab387f87b7b829fabb6b3".equals(sig)) {
                    System.exit(1);
                }
                System.out.printf("{\"status\":\"ok\",\"lang\":\"java\",\"peer_a\":\"%s\",\"peer_b\":\"%s\",\"xor_distance\":\"%s\"}%n",
                        peerA, peerB, dist.toString());
                return;
            }
        }
        AdvanceTetherNode node = new AdvanceTetherNode("java-peer", "advancetether-default-key");
        int boundPort = node.startServer(0);
        System.out.printf("{\"event\":\"listening\",\"peer_id\":\"%s\",\"lang\":\"java\",\"port\":%d}%n",
                node.getPeerId(), boundPort);
    }
}
