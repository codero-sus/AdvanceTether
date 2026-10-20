<?php
declare(strict_types=1);

namespace AdvanceTether;

/**
 * AdvanceTether PHP SDK (ATP/1.0)
 * Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer & Network Tunneling.
 */
class AdvanceTetherNode
{
    public const MAGIC = "AT2P";
    public const VERSION = 1;
    public const HEADER_SIZE = 12;
    public const FLAG_ENCRYPTED = 0x01;

    public const PKT_HELLO        = 0x01;
    public const PKT_HELLO_ACK    = 0x02;
    public const PKT_PING         = 0x03;
    public const PKT_PONG         = 0x04;
    public const PKT_DISCOVER     = 0x05;
    public const PKT_PEER_LIST    = 0x06;
    public const PKT_DHT_PUT      = 0x07;
    public const PKT_DHT_GET      = 0x08;
    public const PKT_DHT_RES      = 0x09;
    public const PKT_MSG          = 0x0A;
    public const PKT_PUBSUB_SUB   = 0x0B;
    public const PKT_PUBSUB_PUB   = 0x0C;
    public const PKT_FILE_OFFER   = 0x0D;
    public const PKT_FILE_CHUNK   = 0x0E;
    public const PKT_FILE_ACK     = 0x0F;
    public const PKT_TUNNEL_OPEN  = 0x10;
    public const PKT_TUNNEL_DATA  = 0x11;
    public const PKT_TUNNEL_CLOSE = 0x12;
    public const PKT_HOLE_PUNCH   = 0x13;

    public string $name;
    public string $peerId;
    public string $networkKey;
    public array $dht = [];

    public function __construct(string $name = "php-peer", string $networkKey = "advancetether-default-key")
    {
        $this->name = $name;
        $this->networkKey = $networkKey;
        $this->peerId = self::generatePeerId("php:{$name}:" . microtime(true));
    }

    public static function sha256Bytes(string $data): string
    {
        return hash("sha256", $data, true);
    }

    public static function sha256Hex(string $data): string
    {
        return hash("sha256", $data, false);
    }

    public static function generatePeerId(?string $seed = null): string
    {
        $raw = $seed ?? bin2hex(random_bytes(16));
        return "atp_" . substr(self::sha256Hex($raw), 0, 16);
    }

    public static function deriveKeys(string $networkKey): array
    {
        return [
            self::sha256Bytes("ATP_ENC:" . $networkKey),
            self::sha256Bytes("ATP_MAC:" . $networkKey),
        ];
    }

    public static function xorDistanceHex(string $peerA, string $peerB): string
    {
        $cleanA = str_starts_with($peerA, "atp_") ? substr($peerA, 4, 16) : substr($peerA, 0, 16);
        $cleanB = str_starts_with($peerB, "atp_") ? substr($peerB, 4, 16) : substr($peerB, 0, 16);
        $bytesA = hex2bin(str_pad($cleanA, 16, "0"));
        $bytesB = hex2bin(str_pad($cleanB, 16, "0"));
        return bin2hex($bytesA ^ $bytesB);
    }

    public static function signEnvelope(array $env, string $networkKey): string
    {
        [, $kMac] = self::deriveKeys($networkKey);
        $canonical = sprintf(
            "%s:%s:%s:%s:%d",
            $env["id"] ?? "",
            $env["type"] ?? "",
            $env["from"] ?? "",
            $env["to"] ?? "",
            $env["ts"] ?? 0
        );
        return substr(hash_hmac("sha256", $canonical, $kMac, false), 0, 32);
    }

    public static function keystreamXor(string $data, string $kEnc, string $nonce): string
    {
        $len = strlen($data);
        $blocks = intdiv($len + 31, 32);
        $streamTotal = "";
        for ($counter = 0; $counter < $blocks; $counter++) {
            $counterBe = pack("N", $counter);
            $streamTotal .= self::sha256Bytes($kEnc . $nonce . $counterBe);
        }
        return $data ^ substr($streamTotal, 0, $len);
    }

    public static function encryptPayload(string $plaintext, string $networkKey, ?string $nonceHex = null): string
    {
        [$kEnc, $kMac] = self::deriveKeys($networkKey);
        if ($nonceHex !== null) {
            $nonce = hex2bin($nonceHex);
        } else {
            $nonce = random_bytes(16);
            $nonceHex = bin2hex($nonce);
        }
        $ciphertext = self::keystreamXor($plaintext, $kEnc, $nonce);
        $tag = hash_hmac("sha256", $nonce . $ciphertext, $kMac, false);
        return json_encode([
            "enc" => "ATP-SHA256-CTR-HMAC",
            "nonce" => $nonceHex,
            "ciphertext" => base64_encode($ciphertext),
            "tag" => $tag,
        ], JSON_UNESCAPED_SLASHES);
    }

    public static function decryptPayload(string $encryptedJson, string $networkKey): string
    {
        [$kEnc, $kMac] = self::deriveKeys($networkKey);
        $env = json_decode($encryptedJson, true);
        if (($env["enc"] ?? "") !== "ATP-SHA256-CTR-HMAC") {
            throw new \RuntimeException("Unsupported ATP encryption scheme");
        }
        $nonce = hex2bin($env["nonce"]);
        $ciphertext = base64_decode($env["ciphertext"], true);
        $expectedTag = hash_hmac("sha256", $nonce . $ciphertext, $kMac, false);
        if (!hash_equals($expectedTag, $env["tag"] ?? "")) {
            throw new \RuntimeException("ATP HMAC authentication tag mismatch");
        }
        return self::keystreamXor($ciphertext, $kEnc, $nonce);
    }

    public static function encodeFrame(int $msgType, array $envelope, bool $encrypt = true, string $networkKey = "advancetether-default-key", ?string $nonceHex = null): string
    {
        $rawJson = json_encode($envelope, JSON_UNESCAPED_SLASHES);
        $flags = 0;
        if ($encrypt) {
            $flags |= self::FLAG_ENCRYPTED;
            $payload = self::encryptPayload($rawJson, $networkKey, $nonceHex);
        } else {
            $payload = $rawJson;
        }
        $header = pack("a4CCCCN", self::MAGIC, self::VERSION, $flags, $msgType, 0, strlen($payload));
        return $header . $payload;
    }

    public static function decodeFrame(string $frameBytes, string $networkKey = "advancetether-default-key"): array
    {
        $hdr = unpack("a4magic/Cversion/Cflags/Cmsg_type/Creserved/Nlength", substr($frameBytes, 0, self::HEADER_SIZE));
        if ($hdr["magic"] !== self::MAGIC || $hdr["version"] !== self::VERSION) {
            throw new \RuntimeException("Invalid ATP frame header");
        }
        $payload = substr($frameBytes, self::HEADER_SIZE, $hdr["length"]);
        if (($hdr["flags"] & self::FLAG_ENCRYPTED) !== 0) {
            $payload = self::decryptPayload($payload, $networkKey);
        }
        return [
            "msg_type" => $hdr["msg_type"],
            "flags" => $hdr["flags"],
            "envelope" => json_decode($payload, true),
        ];
    }
}
