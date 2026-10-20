#ifndef ADVANCETETHER_HPP
#define ADVANCETETHER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "../../c/include/advancetether.h"

namespace advancetether {

struct DecodedFrame {
    uint8_t msg_type;
    uint8_t flags;
    std::string envelope_json;
};

class Crypto {
public:
    static std::string sha256Hex(const std::string& input);
    static std::string generatePeerId(const std::string& seed);
    static uint64_t xorDistance(const std::string& peerA, const std::string& peerB);
    static std::string signEnvelope(
        const std::string& id,
        const std::string& type,
        const std::string& fromPeer,
        const std::string& toPeer,
        int64_t ts,
        const std::string& networkKey
    );
};

class Protocol {
public:
    static std::vector<uint8_t> encodeFrame(
        uint8_t msgType,
        const std::string& envelopeJson,
        bool encrypt,
        const std::string& networkKey,
        const uint8_t* optionalNonce = nullptr
    );

    static DecodedFrame decodeFrame(
        const std::vector<uint8_t>& frameBytes,
        const std::string& networkKey
    );

    static std::string makeEnvelopeJson(
        uint8_t msgType,
        const std::string& fromPeer,
        const std::string& toPeer,
        const std::string& lang,
        const std::string& bodyJson,
        const std::string& networkKey
    );
};

class DHT {
public:
    explicit DHT(std::string selfPeerId);
    void put(const std::string& key, const std::string& value);
    std::string get(const std::string& key) const;
    bool has(const std::string& key) const;

private:
    std::string selfPeerId_;
    std::map<std::string, std::string> store_;
};

class Node {
public:
    Node(std::string name, std::string networkKey = "advancetether-default-key", bool encrypt = true);
    ~Node();

    const std::string& peerId() const { return peerId_; }
    const std::string& name() const { return name_; }
    DHT& dht() { return dht_; }

    int listenOn(int port = 0);
    bool connectAndExchange(const std::string& host, int port, const std::string& messageText, std::string& outRemoteId, std::string& outReplyJson);
    void serveSingleClient();

private:
    std::string name_;
    std::string networkKey_;
    bool encrypt_;
    std::string peerId_;
    int serverFd_;
    int boundPort_;
    DHT dht_;
};

} // namespace advancetether

#endif // ADVANCETETHER_HPP
