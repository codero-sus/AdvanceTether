#include "../include/advancetether.hpp"

#include <stdexcept>
#include <sstream>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace advancetether {

std::string Crypto::sha256Hex(const std::string& input) {
    char hex[65];
    atp_sha256_hex(reinterpret_cast<const uint8_t*>(input.data()), input.size(), hex);
    return std::string(hex);
}

std::string Crypto::generatePeerId(const std::string& seed) {
    char pid[21];
    atp_generate_peer_id(seed.c_str(), pid);
    return std::string(pid);
}

uint64_t Crypto::xorDistance(const std::string& peerA, const std::string& peerB) {
    return atp_xor_distance(peerA.c_str(), peerB.c_str());
}

std::string Crypto::signEnvelope(
    const std::string& id,
    const std::string& type,
    const std::string& fromPeer,
    const std::string& toPeer,
    int64_t ts,
    const std::string& networkKey
) {
    char sig[33];
    atp_sign_envelope_fields(id.c_str(), type.c_str(), fromPeer.c_str(), toPeer.c_str(), ts, networkKey.c_str(), sig);
    return std::string(sig);
}

std::vector<uint8_t> Protocol::encodeFrame(
    uint8_t msgType,
    const std::string& envelopeJson,
    bool encrypt,
    const std::string& networkKey,
    const uint8_t* optionalNonce
) {
    uint8_t* raw = nullptr;
    size_t len = 0;
    if (atp_encode_frame(msgType, envelopeJson.c_str(), encrypt, networkKey.c_str(), optionalNonce, &raw, &len) != 0) {
        throw std::runtime_error("Failed to encode ATP frame");
    }
    std::vector<uint8_t> vec(raw, raw + len);
    free(raw);
    return vec;
}

DecodedFrame Protocol::decodeFrame(
    const std::vector<uint8_t>& frameBytes,
    const std::string& networkKey
) {
    uint8_t msgType = 0, flags = 0;
    char* json = nullptr;
    if (atp_decode_frame(frameBytes.data(), frameBytes.size(), networkKey.c_str(), &msgType, &flags, &json) != 0) {
        throw std::runtime_error("Failed to decode ATP frame");
    }
    DecodedFrame out{msgType, flags, std::string(json)};
    free(json);
    return out;
}

std::string Protocol::makeEnvelopeJson(
    uint8_t msgType,
    const std::string& fromPeer,
    const std::string& toPeer,
    const std::string& lang,
    const std::string& bodyJson,
    const std::string& networkKey
) {
    std::string typeName = atp_packet_type_name(msgType);
    int64_t ts = static_cast<int64_t>(std::time(nullptr)) * 1000LL;
    char msgId[36];
    std::snprintf(msgId, sizeof(msgId), "msg_cpp_%08x%04x", static_cast<unsigned int>(ts), static_cast<unsigned int>(std::rand() & 0xffff));
    std::string sig = Crypto::signEnvelope(msgId, typeName, fromPeer, toPeer, ts, networkKey);

    std::ostringstream oss;
    oss << "{\"v\":1,\"id\":\"" << msgId << "\",\"type\":\"" << typeName
        << "\",\"from\":\"" << fromPeer << "\",\"to\":\"" << toPeer
        << "\",\"lang\":\"" << lang << "\",\"ts\":" << ts
        << ",\"ttl\":6,\"body\":" << bodyJson
        << ",\"sig\":\"" << sig << "\"}";
    return oss.str();
}

DHT::DHT(std::string selfPeerId) : selfPeerId_(std::move(selfPeerId)) {}

void DHT::put(const std::string& key, const std::string& value) {
    store_[key] = value;
}

std::string DHT::get(const std::string& key) const {
    auto it = store_.find(key);
    return it != store_.end() ? it->second : "";
}

bool DHT::has(const std::string& key) const {
    return store_.find(key) != store_.end();
}

Node::Node(std::string name, std::string networkKey, bool encrypt)
    : name_(std::move(name)),
      networkKey_(std::move(networkKey)),
      encrypt_(encrypt),
      peerId_(Crypto::generatePeerId("cpp:" + name_ + ":" + std::to_string(std::time(nullptr)) + ":" + std::to_string(getpid()))),
      serverFd_(-1),
      boundPort_(0),
      dht_(peerId_) {}

Node::~Node() {
    if (serverFd_ >= 0) {
        close(serverFd_);
    }
}

int Node::listenOn(int port) {
    serverFd_ = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serverFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    bind(serverFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(serverFd_, 16);
    socklen_t alen = sizeof(addr);
    getsockname(serverFd_, reinterpret_cast<sockaddr*>(&addr), &alen);
    boundPort_ = ntohs(addr.sin_port);
    return boundPort_;
}

static std::string extractJsonField(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    auto pos = json.find(pat);
    if (pos == std::string::npos) return "*";
    pos += pat.size();
    auto end = json.find('"', pos);
    if (end == std::string::npos) return "*";
    return json.substr(pos, end - pos);
}

bool Node::connectAndExchange(
    const std::string& host,
    int port,
    const std::string& messageText,
    std::string& outRemoteId,
    std::string& outReplyJson
) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(sock);
        return false;
    }

    std::ostringstream helloBody;
    helloBody << "{\"peer_id\":\"" << peerId_ << "\",\"name\":\"" << name_
              << "\",\"lang\":\"cpp\",\"host\":\"127.0.0.1\",\"port\":" << boundPort_ << "}";
    std::string helloEnv = Protocol::makeEnvelopeJson(ATP_PKT_HELLO, peerId_, "*", "cpp", helloBody.str(), networkKey_);
    atp_send_frame_fd(sock, ATP_PKT_HELLO, helloEnv.c_str(), encrypt_, networkKey_.c_str());

    uint8_t rtype = 0, rflags = 0;
    char* ackJson = nullptr;
    if (atp_recv_frame_fd(sock, networkKey_.c_str(), &rtype, &rflags, &ackJson) != 0) {
        close(sock);
        return false;
    }
    std::string ackStr(ackJson);
    free(ackJson);
    outRemoteId = extractJsonField(ackStr, "from");

    if (!messageText.empty()) {
        std::string msgBody = "{\"text\":\"" + messageText + "\",\"rpc\":\"echo\"}";
        std::string msgEnv = Protocol::makeEnvelopeJson(ATP_PKT_MSG, peerId_, outRemoteId, "cpp", msgBody, networkKey_);
        atp_send_frame_fd(sock, ATP_PKT_MSG, msgEnv.c_str(), encrypt_, networkKey_.c_str());

        char* replyRaw = nullptr;
        if (atp_recv_frame_fd(sock, networkKey_.c_str(), &rtype, &rflags, &replyRaw) == 0) {
            outReplyJson = std::string(replyRaw);
            free(replyRaw);
        }
    }

    close(sock);
    return true;
}

void Node::serveSingleClient() {
    if (serverFd_ < 0) return;
    int client = accept(serverFd_, nullptr, nullptr);
    if (client < 0) return;

    uint8_t rtype = 0, rflags = 0;
    char* envJson = nullptr;
    while (atp_recv_frame_fd(client, networkKey_.c_str(), &rtype, &rflags, &envJson) == 0) {
        std::string envStr(envJson);
        free(envJson);
        std::string remoteId = extractJsonField(envStr, "from");
        if (rtype == ATP_PKT_HELLO) {
            std::ostringstream ackBody;
            ackBody << "{\"peer_id\":\"" << peerId_ << "\",\"name\":\"" << name_
                    << "\",\"lang\":\"cpp\",\"host\":\"127.0.0.1\",\"port\":" << boundPort_ << "}";
            std::string ackEnv = Protocol::makeEnvelopeJson(ATP_PKT_HELLO_ACK, peerId_, remoteId, "cpp", ackBody.str(), networkKey_);
            atp_send_frame_fd(client, ATP_PKT_HELLO_ACK, ackEnv.c_str(), encrypt_, networkKey_.c_str());
        } else if (rtype == ATP_PKT_MSG) {
            std::string replyBody = "{\"text\":\"Echo from " + name_ + " (cpp)\"}";
            std::string replyEnv = Protocol::makeEnvelopeJson(ATP_PKT_MSG, peerId_, remoteId, "cpp", replyBody, networkKey_);
            atp_send_frame_fd(client, ATP_PKT_MSG, replyEnv.c_str(), encrypt_, networkKey_.c_str());
        }
    }
    close(client);
}

} // namespace advancetether
