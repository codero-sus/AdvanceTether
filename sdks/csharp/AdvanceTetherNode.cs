using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AdvanceTether
{
    /// <summary>
    /// AdvanceTether C# / .NET SDK (ATP/1.0)
    /// Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer &amp; Network Tunneling.
    /// </summary>
    public class AdvanceTetherNode
    {
        public static readonly byte[] Magic = Encoding.ASCII.GetBytes("AT2P");
        public const byte Version = 1;
        public const int HeaderSize = 12;
        public const byte FlagEncrypted = 0x01;

        public const byte PktHello = 0x01;
        public const byte PktHelloAck = 0x02;
        public const byte PktPing = 0x03;
        public const byte PktPong = 0x04;
        public const byte PktDiscover = 0x05;
        public const byte PktPeerList = 0x06;
        public const byte PktDhtPut = 0x07;
        public const byte PktDhtGet = 0x08;
        public const byte PktDhtRes = 0x09;
        public const byte PktMsg = 0x0A;
        public const byte PktPubSubSub = 0x0B;
        public const byte PktPubSubPub = 0x0C;
        public const byte PktFileOffer = 0x0D;
        public const byte PktFileChunk = 0x0E;
        public const byte PktFileAck = 0x0F;
        public const byte PktTunnelOpen = 0x10;
        public const byte PktTunnelData = 0x11;
        public const byte PktTunnelClose = 0x12;
        public const byte PktHolePunch = 0x13;

        public string Name { get; }
        public string PeerId { get; }
        public string NetworkKey { get; }
        public ConcurrentDictionary<string, string> DhtStore { get; } = new();
        private TcpListener? _listener;

        public AdvanceTetherNode(string name, string networkKey = "advancetether-default-key")
        {
            Name = name;
            NetworkKey = networkKey;
            PeerId = GeneratePeerId($"csharp:{name}:{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}");
        }

        public static byte[] Sha256Bytes(byte[] data) => SHA256.HashData(data);

        public static string Sha256Hex(byte[] data) => Convert.ToHexString(Sha256Bytes(data)).ToLowerInvariant();

        public static string GeneratePeerId(string seed)
        {
            string hex = Sha256Hex(Encoding.UTF8.GetBytes(seed));
            return "atp_" + hex.Substring(0, 16);
        }

        public static ulong IdToUInt64(string peerId)
        {
            string clean = peerId.StartsWith("atp_") ? peerId.Substring(4) : peerId;
            clean = clean.PadRight(16, '0').Substring(0, 16);
            return Convert.ToUInt64(clean, 16);
        }

        public static ulong XorDistance(string peerA, string peerB) => IdToUInt64(peerA) ^ IdToUInt64(peerB);

        public static string SignEnvelopeFields(string id, string type, string fromPeer, string toPeer, long ts, string networkKey)
        {
            byte[] kMac = Sha256Bytes(Encoding.UTF8.GetBytes("ATP_MAC:" + networkKey));
            string canonical = $"{id}:{type}:{fromPeer}:{toPeer}:{ts}";
            using var hmac = new HMACSHA256(kMac);
            byte[] mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
            return Convert.ToHexString(mac).ToLowerInvariant().Substring(0, 32);
        }

        private static byte[] KeystreamXor(byte[] data, byte[] kEnc, byte[] nonce)
        {
            byte[] output = new byte[data.Length];
            int blocks = (data.Length + 31) / 32;
            byte[] blockIn = new byte[52];
            Buffer.BlockCopy(kEnc, 0, blockIn, 0, 32);
            Buffer.BlockCopy(nonce, 0, blockIn, 32, 16);

            for (uint counter = 0; counter < blocks; counter++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(blockIn.AsSpan(48, 4), counter);
                byte[] stream = Sha256Bytes(blockIn);
                int start = (int)counter * 32;
                int end = Math.Min(start + 32, data.Length);
                for (int i = start; i < end; i++)
                {
                    output[i] = (byte)(data[i] ^ stream[i - start]);
                }
            }
            return output;
        }

        public static byte[] EncryptPayload(byte[] plaintext, string networkKey, string? nonceHex = null)
        {
            byte[] kEnc = Sha256Bytes(Encoding.UTF8.GetBytes("ATP_ENC:" + networkKey));
            byte[] kMac = Sha256Bytes(Encoding.UTF8.GetBytes("ATP_MAC:" + networkKey));
            byte[] nonce = !string.IsNullOrEmpty(nonceHex)
                ? Convert.FromHexString(nonceHex)
                : RandomNumberGenerator.GetBytes(16);
            string actualNonceHex = Convert.ToHexString(nonce).ToLowerInvariant();

            byte[] ciphertext = KeystreamXor(plaintext, kEnc, nonce);
            byte[] macInput = new byte[nonce.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, macInput, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, macInput, nonce.Length, ciphertext.Length);

            using var hmac = new HMACSHA256(kMac);
            string tag = Convert.ToHexString(hmac.ComputeHash(macInput)).ToLowerInvariant();
            string b64 = Convert.ToBase64String(ciphertext);

            string json = $"{{\"enc\":\"ATP-SHA256-CTR-HMAC\",\"nonce\":\"{actualNonceHex}\",\"ciphertext\":\"{b64}\",\"tag\":\"{tag}\"}}";
            return Encoding.UTF8.GetBytes(json);
        }

        public static byte[] EncodeFrame(byte msgType, string envelopeJson, bool encrypt, string networkKey, string? nonceHex = null)
        {
            byte flags = 0;
            byte[] payload = Encoding.UTF8.GetBytes(envelopeJson);
            if (encrypt)
            {
                flags |= FlagEncrypted;
                payload = EncryptPayload(payload, networkKey, nonceHex);
            }

            byte[] frame = new byte[HeaderSize + payload.Length];
            Buffer.BlockCopy(Magic, 0, frame, 0, 4);
            frame[4] = Version;
            frame[5] = flags;
            frame[6] = msgType;
            frame[7] = 0;
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(8, 4), (uint)payload.Length);
            Buffer.BlockCopy(payload, 0, frame, HeaderSize, payload.Length);
            return frame;
        }

        public int StartListener(int port = 0)
        {
            _listener = new TcpListener(IPAddress.Loopback, port);
            _listener.Start();
            return ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public void StopListener() => _listener?.Stop();
    }
}
