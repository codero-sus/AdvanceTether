#define _POSIX_C_SOURCE 200809L
#include "../include/advancetether.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static int extract_str(const char *json, const char *key, char *out, size_t max_len) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < max_len) out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

static char *build_envelope(
    uint8_t msg_type,
    const char *from_peer,
    const char *to_peer,
    const char *body_json,
    const char *network_key
) {
    const char *tname = atp_packet_type_name(msg_type);
    int64_t ts = (int64_t)time(NULL) * 1000LL;
    char msg_id[32];
    snprintf(msg_id, sizeof(msg_id), "msg_c_%08x%04x", (unsigned int)ts, (unsigned int)(rand() & 0xffff));
    char sig[33];
    atp_sign_envelope_fields(msg_id, tname, from_peer, to_peer, ts, network_key, sig);

    size_t cap = strlen(body_json) + 512;
    char *env = (char *)malloc(cap);
    snprintf(
        env, cap,
        "{\"v\":1,\"id\":\"%s\",\"type\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"lang\":\"c\",\"ts\":%lld,\"ttl\":6,\"body\":%s,\"sig\":\"%s\"}",
        msg_id, tname, from_peer, to_peer, (long long)ts, body_json, sig
    );
    return env;
}

static int run_self_test(void) {
    const char *net_key = "advancetether-universal-key-2026";
    char peer_a[21], peer_b[21];
    atp_generate_peer_id("seed-alpha", peer_a);
    atp_generate_peer_id("seed-beta", peer_b);

    if (strcmp(peer_a, "atp_ba316cd7abc9b7dc") != 0 || strcmp(peer_b, "atp_d9c30acfd5686611") != 0) {
        fprintf(stderr, "C peer_id test vector mismatch: %s / %s\n", peer_a, peer_b);
        return 1;
    }

    uint64_t dist = atp_xor_distance(peer_a, peer_b);
    if (dist != 7201931009508626893ULL) {
        fprintf(stderr, "C XOR distance mismatch: %llu\n", (unsigned long long)dist);
        return 1;
    }

    char sig[33];
    atp_sign_envelope_fields("msg_0123456789abcdef", "MSG", peer_a, peer_b, 1792454400000LL, net_key, sig);
    if (strcmp(sig, "278c381e5f2ab387f87b7b829fabb6b3") != 0) {
        fprintf(stderr, "C signature mismatch: %s\n", sig);
        return 1;
    }

    const char *env_json = "{\"v\":1,\"id\":\"msg_0123456789abcdef\",\"type\":\"MSG\",\"from\":\"atp_ba316cd7abc9b7dc\",\"to\":\"atp_d9c30acfd5686611\",\"lang\":\"polyglot\",\"ts\":1792454400000,\"ttl\":6,\"body\":{\"text\":\"Peer-to-Peer for all.\"},\"sig\":\"278c381e5f2ab387f87b7b829fabb6b3\"}";
    uint8_t nonce[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (atp_encode_frame(ATP_PKT_MSG, env_json, true, net_key, nonce, &frame, &frame_len) != 0) {
        return 1;
    }

    uint8_t msg_type = 0, flags = 0;
    char *decoded_json = NULL;
    if (atp_decode_frame(frame, frame_len, net_key, &msg_type, &flags, &decoded_json) != 0) {
        free(frame);
        return 1;
    }
    if (strcmp(decoded_json, env_json) != 0) {
        fprintf(stderr, "C decrypt roundtrip mismatch\n");
        free(frame);
        free(decoded_json);
        return 1;
    }
    free(frame);
    free(decoded_json);

    printf("{\"status\":\"ok\",\"lang\":\"c\",\"peer_a\":\"%s\",\"peer_b\":\"%s\",\"xor_distance\":\"%llu\"}\n",
           peer_a, peer_b, (unsigned long long)dist);
    return 0;
}

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    const char *name = "c-peer";
    const char *connect_arg = NULL;
    const char *send_text = NULL;
    const char *key = "advancetether-default-key";
    int port = 0;
    bool self_test = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--self-test") == 0) self_test = true;
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) connect_arg = argv[++i];
        else if (strcmp(argv[i], "--send") == 0 && i + 1 < argc) send_text = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
    }

    if (self_test) {
        return run_self_test();
    }

    char seed[128], peer_id[21];
    snprintf(seed, sizeof(seed), "c:%s:%d:%ld", name, getpid(), (long)time(NULL));
    atp_generate_peer_id(seed, peer_id);

    if (connect_arg) {
        char host[128];
        int remote_port = 0;
        const char *colon = strrchr(connect_arg, ':');
        if (!colon) return 1;
        size_t hlen = (size_t)(colon - connect_arg);
        memcpy(host, connect_arg, hlen);
        host[hlen] = '\0';
        remote_port = atoi(colon + 1);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)remote_port);
        inet_pton(AF_INET, host, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            perror("connect");
            close(sock);
            return 1;
        }

        char hello_body[256];
        snprintf(hello_body, sizeof(hello_body),
                 "{\"peer_id\":\"%s\",\"name\":\"%s\",\"lang\":\"c\",\"host\":\"127.0.0.1\",\"port\":%d}",
                 peer_id, name, port);
        char *hello_env = build_envelope(ATP_PKT_HELLO, peer_id, "*", hello_body, key);
        atp_send_frame_fd(sock, ATP_PKT_HELLO, hello_env, true, key);
        free(hello_env);

        uint8_t rtype = 0, rflags = 0;
        char *ack_json = NULL;
        if (atp_recv_frame_fd(sock, key, &rtype, &rflags, &ack_json) == 0) {
            char remote_id[64] = "*";
            extract_str(ack_json, "from", remote_id, sizeof(remote_id));
            printf("{\"event\":\"peer_connected\",\"node\":\"%s\",\"peer\":\"%s\",\"lang\":\"c\"}\n", peer_id, remote_id);
            fflush(stdout);
            free(ack_json);

            if (send_text) {
                char msg_body[512];
                snprintf(msg_body, sizeof(msg_body), "{\"text\":\"%s\",\"rpc\":\"echo\"}", send_text);
                char *msg_env = build_envelope(ATP_PKT_MSG, peer_id, remote_id, msg_body, key);
                atp_send_frame_fd(sock, ATP_PKT_MSG, msg_env, true, key);
                free(msg_env);

                char *reply_json = NULL;
                if (atp_recv_frame_fd(sock, key, &rtype, &rflags, &reply_json) == 0) {
                    printf("{\"event\":\"message\",\"node\":\"%s\",\"raw\":%s}\n", peer_id, reply_json);
                    fflush(stdout);
                    free(reply_json);
                }
            }
        }
        close(sock);
        return 0;
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = htons((uint16_t)port);
    bind(srv, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    listen(srv, 16);

    socklen_t alen = sizeof(bind_addr);
    getsockname(srv, (struct sockaddr *)&bind_addr, &alen);
    int actual_port = ntohs(bind_addr.sin_port);
    printf("{\"event\":\"listening\",\"peer_id\":\"%s\",\"name\":\"%s\",\"lang\":\"c\",\"host\":\"127.0.0.1\",\"port\":%d}\n",
           peer_id, name, actual_port);
    fflush(stdout);

    int client = accept(srv, NULL, NULL);
    if (client >= 0) {
        uint8_t rtype = 0, rflags = 0;
        char *env_json = NULL;
        while (atp_recv_frame_fd(client, key, &rtype, &rflags, &env_json) == 0) {
            char remote_id[64] = "*";
            extract_str(env_json, "from", remote_id, sizeof(remote_id));
            if (rtype == ATP_PKT_HELLO) {
                char ack_body[256];
                snprintf(ack_body, sizeof(ack_body),
                         "{\"peer_id\":\"%s\",\"name\":\"%s\",\"lang\":\"c\",\"host\":\"127.0.0.1\",\"port\":%d}",
                         peer_id, name, actual_port);
                char *ack_env = build_envelope(ATP_PKT_HELLO_ACK, peer_id, remote_id, ack_body, key);
                atp_send_frame_fd(client, ATP_PKT_HELLO_ACK, ack_env, true, key);
                free(ack_env);
            } else if (rtype == ATP_PKT_MSG) {
                printf("{\"event\":\"message\",\"node\":\"%s\",\"raw\":%s}\n", peer_id, env_json);
                fflush(stdout);
                char reply_body[256];
                snprintf(reply_body, sizeof(reply_body), "{\"text\":\"Echo from %s (c)\"}", name);
                char *reply_env = build_envelope(ATP_PKT_MSG, peer_id, remote_id, reply_body, key);
                atp_send_frame_fd(client, ATP_PKT_MSG, reply_env, true, key);
                free(reply_env);
            }
            free(env_json);
        }
        close(client);
    }
    close(srv);
    return 0;
}
