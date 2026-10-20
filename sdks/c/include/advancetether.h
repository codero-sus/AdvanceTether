#ifndef ADVANCETETHER_H
#define ADVANCETETHER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ATP_MAGIC_0 'A'
#define ATP_MAGIC_1 'T'
#define ATP_MAGIC_2 '2'
#define ATP_MAGIC_3 'P'
#define ATP_VERSION 1
#define ATP_HEADER_SIZE 12
#define ATP_FLAG_ENCRYPTED 0x01
#define ATP_FLAG_COMPRESSED 0x02
#define ATP_FLAG_BINARY 0x04
#define ATP_FLAG_ACK_REQ 0x08

typedef enum {
    ATP_PKT_HELLO        = 0x01,
    ATP_PKT_HELLO_ACK    = 0x02,
    ATP_PKT_PING         = 0x03,
    ATP_PKT_PONG         = 0x04,
    ATP_PKT_DISCOVER     = 0x05,
    ATP_PKT_PEER_LIST    = 0x06,
    ATP_PKT_DHT_PUT      = 0x07,
    ATP_PKT_DHT_GET      = 0x08,
    ATP_PKT_DHT_RES      = 0x09,
    ATP_PKT_MSG          = 0x0A,
    ATP_PKT_PUBSUB_SUB   = 0x0B,
    ATP_PKT_PUBSUB_PUB   = 0x0C,
    ATP_PKT_FILE_OFFER   = 0x0D,
    ATP_PKT_FILE_CHUNK   = 0x0E,
    ATP_PKT_FILE_ACK     = 0x0F,
    ATP_PKT_TUNNEL_OPEN  = 0x10,
    ATP_PKT_TUNNEL_DATA  = 0x11,
    ATP_PKT_TUNNEL_CLOSE = 0x12,
    ATP_PKT_HOLE_PUNCH   = 0x13
} atp_packet_type_t;

void atp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void atp_sha256_hex(const uint8_t *data, size_t len, char out_hex[65]);
void atp_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32]);
void atp_generate_peer_id(const char *seed, char out_peer_id[21]);
uint64_t atp_id_to_u64(const char *peer_id);
uint64_t atp_xor_distance(const char *peer_a, const char *peer_b);

void atp_sign_envelope_fields(
    const char *id,
    const char *type,
    const char *from_peer,
    const char *to_peer,
    int64_t ts,
    const char *network_key,
    char out_sig[33]
);

int atp_encrypt_payload(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char *network_key,
    const uint8_t nonce[16],
    char **out_json,
    size_t *out_json_len
);

int atp_decrypt_payload(
    const char *encrypted_json,
    size_t encrypted_json_len,
    const char *network_key,
    uint8_t **out_plaintext,
    size_t *out_plaintext_len
);

int atp_encode_frame(
    uint8_t msg_type,
    const char *envelope_json,
    bool encrypt,
    const char *network_key,
    const uint8_t *optional_nonce,
    uint8_t **out_frame,
    size_t *out_frame_len
);

int atp_decode_frame(
    const uint8_t *frame,
    size_t frame_len,
    const char *network_key,
    uint8_t *out_msg_type,
    uint8_t *out_flags,
    char **out_envelope_json
);

int atp_send_frame_fd(
    int sock_fd,
    uint8_t msg_type,
    const char *envelope_json,
    bool encrypt,
    const char *network_key
);

int atp_recv_frame_fd(
    int sock_fd,
    const char *network_key,
    uint8_t *out_msg_type,
    uint8_t *out_flags,
    char **out_envelope_json
);

const char *atp_packet_type_name(uint8_t msg_type);

#ifdef __cplusplus
}
#endif

#endif /* ADVANCETETHER_H */
