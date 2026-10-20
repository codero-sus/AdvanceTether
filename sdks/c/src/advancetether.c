#define _POSIX_C_SOURCE 200809L
#include "../include/advancetether.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

/* --- Standalone RFC 6234 SHA-256 --- */
typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;
    for (i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void atp_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx_t ctx;
    ctx.state[0] = 0x6a09e667UL; ctx.state[1] = 0xbb67ae85UL;
    ctx.state[2] = 0x3c6ef372UL; ctx.state[3] = 0xa54ff53aUL;
    ctx.state[4] = 0x510e527fUL; ctx.state[5] = 0x9b05688cUL;
    ctx.state[6] = 0x1f83d9abUL; ctx.state[7] = 0x5be0cd19UL;
    ctx.bitcount = 0;

    size_t idx = 0;
    for (size_t i = 0; i < len; ++i) {
        ctx.buffer[idx++] = data[i];
        if (idx == 64) {
            sha256_transform(&ctx, ctx.buffer);
            ctx.bitcount += 512;
            idx = 0;
        }
    }
    ctx.bitcount += idx * 8;
    ctx.buffer[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx.buffer[idx++] = 0x00;
        sha256_transform(&ctx, ctx.buffer);
        idx = 0;
    }
    while (idx < 56) ctx.buffer[idx++] = 0x00;
    for (int i = 7; i >= 0; --i) {
        ctx.buffer[56 + (7 - i)] = (uint8_t)((ctx.bitcount >> (i * 8)) & 0xff);
    }
    sha256_transform(&ctx, ctx.buffer);
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)((ctx.state[i] >> 24) & 0xff);
        out[i * 4 + 1] = (uint8_t)((ctx.state[i] >> 16) & 0xff);
        out[i * 4 + 2] = (uint8_t)((ctx.state[i] >> 8) & 0xff);
        out[i * 4 + 3] = (uint8_t)(ctx.state[i] & 0xff);
    }
}

void atp_sha256_hex(const uint8_t *data, size_t len, char out_hex[65]) {
    uint8_t hash[32];
    atp_sha256(data, len, hash);
    for (int i = 0; i < 32; ++i) {
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    }
    out_hex[64] = '\0';
}

void atp_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    if (key_len > 64) {
        atp_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; ++i) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    uint8_t *inner_buf = (uint8_t *)malloc(64 + data_len);
    memcpy(inner_buf, k_ipad, 64);
    if (data_len > 0) memcpy(inner_buf + 64, data, data_len);
    uint8_t inner_hash[32];
    atp_sha256(inner_buf, 64 + data_len, inner_hash);
    free(inner_buf);

    uint8_t outer_buf[96];
    memcpy(outer_buf, k_opad, 64);
    memcpy(outer_buf + 64, inner_hash, 32);
    atp_sha256(outer_buf, 96, out);
}

/* --- Base64 Encode/Decode --- */
static const char B64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = B64_TABLE[(triple >> 18) & 0x3F];
        out[j++] = B64_TABLE[(triple >> 12) & 0x3F];
        out[j++] = B64_TABLE[(triple >> 6) & 0x3F];
        out[j++] = B64_TABLE[triple & 0x3F];
    }
    size_t mod = len % 3;
    if (mod == 1) { out[out_len - 1] = '='; out[out_len - 2] = '='; }
    else if (mod == 2) { out[out_len - 1] = '='; }
    out[out_len] = '\0';
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *str, size_t len, size_t *out_len) {
    if (len % 4 != 0) return NULL;
    size_t olen = (len / 4) * 3;
    if (len > 0 && str[len - 1] == '=') olen--;
    if (len > 1 && str[len - 2] == '=') olen--;
    uint8_t *out = (uint8_t *)malloc(olen + 1);
    size_t i = 0, j = 0;
    while (i < len) {
        int a = str[i] == '=' ? 0 : b64_val(str[i]); i++;
        int b = str[i] == '=' ? 0 : b64_val(str[i]); i++;
        int c = str[i] == '=' ? 0 : b64_val(str[i]); i++;
        int d = str[i] == '=' ? 0 : b64_val(str[i]); i++;
        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        if (j < olen) out[j++] = (triple >> 16) & 0xFF;
        if (j < olen) out[j++] = (triple >> 8) & 0xFF;
        if (j < olen) out[j++] = triple & 0xFF;
    }
    out[olen] = '\0';
    *out_len = olen;
    return out;
}

/* --- Peer ID & XOR Distance --- */
void atp_generate_peer_id(const char *seed, char out_peer_id[21]) {
    char hex[65];
    atp_sha256_hex((const uint8_t *)seed, strlen(seed), hex);
    snprintf(out_peer_id, 21, "atp_%.16s", hex);
}

uint64_t atp_id_to_u64(const char *peer_id) {
    const char *p = (strncmp(peer_id, "atp_", 4) == 0) ? peer_id + 4 : peer_id;
    char buf[17];
    memset(buf, '0', 16);
    buf[16] = '\0';
    size_t n = strlen(p);
    if (n > 16) n = 16;
    memcpy(buf, p, n);
    return strtoull(buf, NULL, 16);
}

uint64_t atp_xor_distance(const char *peer_a, const char *peer_b) {
    return atp_id_to_u64(peer_a) ^ atp_id_to_u64(peer_b);
}

static void derive_keys(const char *network_key, uint8_t k_enc[32], uint8_t k_mac[32]) {
    size_t klen = strlen(network_key);
    char *enc_in = (char *)malloc(8 + klen + 1);
    char *mac_in = (char *)malloc(8 + klen + 1);
    memcpy(enc_in, "ATP_ENC:", 8);
    memcpy(enc_in + 8, network_key, klen);
    memcpy(mac_in, "ATP_MAC:", 8);
    memcpy(mac_in + 8, network_key, klen);
    atp_sha256((const uint8_t *)enc_in, 8 + klen, k_enc);
    atp_sha256((const uint8_t *)mac_in, 8 + klen, k_mac);
    free(enc_in);
    free(mac_in);
}

void atp_sign_envelope_fields(
    const char *id,
    const char *type,
    const char *from_peer,
    const char *to_peer,
    int64_t ts,
    const char *network_key,
    char out_sig[33]
) {
    uint8_t k_enc[32], k_mac[32], mac[32];
    derive_keys(network_key, k_enc, k_mac);
    char canonical[512];
    int len = snprintf(canonical, sizeof(canonical), "%s:%s:%s:%s:%lld",
                       id ? id : "", type ? type : "", from_peer ? from_peer : "",
                       to_peer ? to_peer : "", (long long)ts);
    atp_hmac_sha256(k_mac, 32, (const uint8_t *)canonical, (size_t)len, mac);
    for (int i = 0; i < 16; ++i) {
        snprintf(out_sig + (i * 2), 3, "%02x", mac[i]);
    }
    out_sig[32] = '\0';
}

static void keystream_xor(const uint8_t *in, size_t len, const uint8_t k_enc[32], const uint8_t nonce[16], uint8_t *out) {
    size_t blocks = (len + 31) / 32;
    uint8_t block_input[52];
    memcpy(block_input, k_enc, 32);
    memcpy(block_input + 32, nonce, 16);

    for (size_t c = 0; c < blocks; ++c) {
        block_input[48] = (uint8_t)((c >> 24) & 0xFF);
        block_input[49] = (uint8_t)((c >> 16) & 0xFF);
        block_input[50] = (uint8_t)((c >> 8) & 0xFF);
        block_input[51] = (uint8_t)(c & 0xFF);
        uint8_t stream[32];
        atp_sha256(block_input, 52, stream);
        size_t start = c * 32;
        size_t end = (start + 32 < len) ? (start + 32) : len;
        for (size_t i = start; i < end; ++i) {
            out[i] = in[i] ^ stream[i - start];
        }
    }
}

int atp_encrypt_payload(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char *network_key,
    const uint8_t nonce_in[16],
    char **out_json,
    size_t *out_json_len
) {
    uint8_t k_enc[32], k_mac[32], nonce[16];
    derive_keys(network_key, k_enc, k_mac);
    if (nonce_in) {
        memcpy(nonce, nonce_in, 16);
    } else {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            if (read(fd, nonce, 16) != 16) memset(nonce, 0x42, 16);
            close(fd);
        } else {
            for (int i = 0; i < 16; ++i) nonce[i] = (uint8_t)(rand() & 0xFF);
        }
    }
    uint8_t *ciphertext = (uint8_t *)malloc(plaintext_len + 1);
    keystream_xor(plaintext, plaintext_len, k_enc, nonce, ciphertext);

    uint8_t *mac_data = (uint8_t *)malloc(16 + plaintext_len);
    memcpy(mac_data, nonce, 16);
    memcpy(mac_data + 16, ciphertext, plaintext_len);
    uint8_t tag[32];
    atp_hmac_sha256(k_mac, 32, mac_data, 16 + plaintext_len, tag);
    free(mac_data);

    char nonce_hex[33], tag_hex[65];
    for (int i = 0; i < 16; ++i) snprintf(nonce_hex + (i * 2), 3, "%02x", nonce[i]);
    nonce_hex[32] = '\0';
    for (int i = 0; i < 32; ++i) snprintf(tag_hex + (i * 2), 3, "%02x", tag[i]);
    tag_hex[64] = '\0';

    char *b64_ct = b64_encode(ciphertext, plaintext_len);
    free(ciphertext);

    size_t cap = strlen(b64_ct) + 256;
    char *json = (char *)malloc(cap);
    int written = snprintf(
        json, cap,
        "{\"enc\":\"ATP-SHA256-CTR-HMAC\",\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\"}",
        nonce_hex, b64_ct, tag_hex
    );
    free(b64_ct);
    *out_json = json;
    *out_json_len = (size_t)written;
    return 0;
}

static int extract_json_string(const char *json, const char *key, char *out, size_t max_len) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *p = strstr(json, pattern);
    if (!p) {
        snprintf(pattern, sizeof(pattern), "\"%s\": \"", key);
        p = strstr(json, pattern);
        if (!p) return -1;
    }
    p += strlen(pattern);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < max_len) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int val = 0;
        if (sscanf(hex + (i * 2), "%02x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

int atp_decrypt_payload(
    const char *encrypted_json,
    size_t encrypted_json_len,
    const char *network_key,
    uint8_t **out_plaintext,
    size_t *out_plaintext_len
) {
    (void)encrypted_json_len;
    char nonce_hex[64], tag_hex[128];
    char *ct_b64 = (char *)malloc(encrypted_json_len + 1);
    if (extract_json_string(encrypted_json, "nonce", nonce_hex, sizeof(nonce_hex)) != 0 ||
        extract_json_string(encrypted_json, "ciphertext", ct_b64, encrypted_json_len + 1) != 0 ||
        extract_json_string(encrypted_json, "tag", tag_hex, sizeof(tag_hex)) != 0) {
        free(ct_b64);
        return -1;
    }

    uint8_t nonce[16];
    if (hex_to_bytes(nonce_hex, nonce, 16) != 0) {
        free(ct_b64);
        return -1;
    }
    size_t ct_len = 0;
    uint8_t *ct = b64_decode(ct_b64, strlen(ct_b64), &ct_len);
    free(ct_b64);
    if (!ct) return -1;

    uint8_t k_enc[32], k_mac[32];
    derive_keys(network_key, k_enc, k_mac);

    uint8_t *mac_data = (uint8_t *)malloc(16 + ct_len);
    memcpy(mac_data, nonce, 16);
    memcpy(mac_data + 16, ct, ct_len);
    uint8_t expected_tag[32];
    atp_hmac_sha256(k_mac, 32, mac_data, 16 + ct_len, expected_tag);
    free(mac_data);

    char expected_hex[65];
    for (int i = 0; i < 32; ++i) snprintf(expected_hex + (i * 2), 3, "%02x", expected_tag[i]);
    expected_hex[64] = '\0';

    if (strcmp(expected_hex, tag_hex) != 0) {
        free(ct);
        return -2;
    }

    uint8_t *pt = (uint8_t *)malloc(ct_len + 1);
    keystream_xor(ct, ct_len, k_enc, nonce, pt);
    pt[ct_len] = '\0';
    free(ct);
    *out_plaintext = pt;
    *out_plaintext_len = ct_len;
    return 0;
}

int atp_encode_frame(
    uint8_t msg_type,
    const char *envelope_json,
    bool encrypt,
    const char *network_key,
    const uint8_t *optional_nonce,
    uint8_t **out_frame,
    size_t *out_frame_len
) {
    uint8_t flags = 0;
    const uint8_t *payload = (const uint8_t *)envelope_json;
    size_t payload_len = strlen(envelope_json);
    char *enc_json = NULL;

    if (encrypt) {
        flags |= ATP_FLAG_ENCRYPTED;
        if (atp_encrypt_payload(payload, payload_len, network_key, optional_nonce, &enc_json, &payload_len) != 0) {
            return -1;
        }
        payload = (const uint8_t *)enc_json;
    }

    uint8_t *frame = (uint8_t *)malloc(ATP_HEADER_SIZE + payload_len);
    frame[0] = ATP_MAGIC_0;
    frame[1] = ATP_MAGIC_1;
    frame[2] = ATP_MAGIC_2;
    frame[3] = ATP_MAGIC_3;
    frame[4] = ATP_VERSION;
    frame[5] = flags;
    frame[6] = msg_type;
    frame[7] = 0;
    frame[8]  = (uint8_t)((payload_len >> 24) & 0xFF);
    frame[9]  = (uint8_t)((payload_len >> 16) & 0xFF);
    frame[10] = (uint8_t)((payload_len >> 8) & 0xFF);
    frame[11] = (uint8_t)(payload_len & 0xFF);
    memcpy(frame + ATP_HEADER_SIZE, payload, payload_len);

    if (enc_json) free(enc_json);
    *out_frame = frame;
    *out_frame_len = ATP_HEADER_SIZE + payload_len;
    return 0;
}

int atp_decode_frame(
    const uint8_t *frame,
    size_t frame_len,
    const char *network_key,
    uint8_t *out_msg_type,
    uint8_t *out_flags,
    char **out_envelope_json
) {
    if (frame_len < ATP_HEADER_SIZE) return -1;
    if (frame[0] != 'A' || frame[1] != 'T' || frame[2] != '2' || frame[3] != 'P') return -2;
    if (frame[4] != ATP_VERSION) return -3;
    uint8_t flags = frame[5];
    uint8_t msg_type = frame[6];
    uint32_t payload_len = ((uint32_t)frame[8] << 24) |
                           ((uint32_t)frame[9] << 16) |
                           ((uint32_t)frame[10] << 8) |
                           ((uint32_t)frame[11]);
    if (frame_len < ATP_HEADER_SIZE + payload_len) return -4;

    const uint8_t *payload = frame + ATP_HEADER_SIZE;
    if (flags & ATP_FLAG_ENCRYPTED) {
        char *tmp = (char *)malloc(payload_len + 1);
        memcpy(tmp, payload, payload_len);
        tmp[payload_len] = '\0';
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int rc = atp_decrypt_payload(tmp, payload_len, network_key, &pt, &pt_len);
        free(tmp);
        if (rc != 0) return -5;
        *out_envelope_json = (char *)pt;
    } else {
        char *json = (char *)malloc(payload_len + 1);
        memcpy(json, payload, payload_len);
        json[payload_len] = '\0';
        *out_envelope_json = json;
    }
    if (out_msg_type) *out_msg_type = msg_type;
    if (out_flags) *out_flags = flags;
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

int atp_send_frame_fd(
    int sock_fd,
    uint8_t msg_type,
    const char *envelope_json,
    bool encrypt,
    const char *network_key
) {
    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (atp_encode_frame(msg_type, envelope_json, encrypt, network_key, NULL, &frame, &frame_len) != 0) {
        return -1;
    }
    int rc = write_all(sock_fd, frame, frame_len);
    free(frame);
    return rc;
}

int atp_recv_frame_fd(
    int sock_fd,
    const char *network_key,
    uint8_t *out_msg_type,
    uint8_t *out_flags,
    char **out_envelope_json
) {
    uint8_t header[ATP_HEADER_SIZE];
    if (read_all(sock_fd, header, ATP_HEADER_SIZE) != 0) return -1;
    if (header[0] != 'A' || header[1] != 'T' || header[2] != '2' || header[3] != 'P') return -2;
    uint32_t payload_len = ((uint32_t)header[8] << 24) |
                           ((uint32_t)header[9] << 16) |
                           ((uint32_t)header[10] << 8) |
                           ((uint32_t)header[11]);
    if (payload_len > 16 * 1024 * 1024) return -3;
    uint8_t *full_frame = (uint8_t *)malloc(ATP_HEADER_SIZE + payload_len);
    memcpy(full_frame, header, ATP_HEADER_SIZE);
    if (read_all(sock_fd, full_frame + ATP_HEADER_SIZE, payload_len) != 0) {
        free(full_frame);
        return -4;
    }
    int rc = atp_decode_frame(full_frame, ATP_HEADER_SIZE + payload_len, network_key, out_msg_type, out_flags, out_envelope_json);
    free(full_frame);
    return rc;
}

const char *atp_packet_type_name(uint8_t msg_type) {
    switch (msg_type) {
        case ATP_PKT_HELLO: return "HELLO";
        case ATP_PKT_HELLO_ACK: return "HELLO_ACK";
        case ATP_PKT_PING: return "PING";
        case ATP_PKT_PONG: return "PONG";
        case ATP_PKT_DISCOVER: return "DISCOVER";
        case ATP_PKT_PEER_LIST: return "PEER_LIST";
        case ATP_PKT_DHT_PUT: return "DHT_PUT";
        case ATP_PKT_DHT_GET: return "DHT_GET";
        case ATP_PKT_DHT_RES: return "DHT_RES";
        case ATP_PKT_MSG: return "MSG";
        case ATP_PKT_PUBSUB_SUB: return "PUBSUB_SUB";
        case ATP_PKT_PUBSUB_PUB: return "PUBSUB_PUB";
        case ATP_PKT_FILE_OFFER: return "FILE_OFFER";
        case ATP_PKT_FILE_CHUNK: return "FILE_CHUNK";
        case ATP_PKT_FILE_ACK: return "FILE_ACK";
        case ATP_PKT_TUNNEL_OPEN: return "TUNNEL_OPEN";
        case ATP_PKT_TUNNEL_DATA: return "TUNNEL_DATA";
        case ATP_PKT_TUNNEL_CLOSE: return "TUNNEL_CLOSE";
        case ATP_PKT_HOLE_PUNCH: return "HOLE_PUNCH";
        default: return "MSG";
    }
}
