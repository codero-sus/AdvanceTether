#include "../include/advancetether.hpp"

#include <iostream>
#include <cassert>
#include <cstring>

using namespace advancetether;

static int runSelfTest() {
    const std::string netKey = "advancetether-universal-key-2026";
    std::string peerA = Crypto::generatePeerId("seed-alpha");
    std::string peerB = Crypto::generatePeerId("seed-beta");

    assert(peerA == "atp_ba316cd7abc9b7dc");
    assert(peerB == "atp_d9c30acfd5686611");

    uint64_t dist = Crypto::xorDistance(peerA, peerB);
    assert(dist == 7201931009508626893ULL);

    std::string sig = Crypto::signEnvelope("msg_0123456789abcdef", "MSG", peerA, peerB, 1792454400000LL, netKey);
    assert(sig == "278c381e5f2ab387f87b7b829fabb6b3");

    std::string envJson = "{\"v\":1,\"id\":\"msg_0123456789abcdef\",\"type\":\"MSG\",\"from\":\"atp_ba316cd7abc9b7dc\",\"to\":\"atp_d9c30acfd5686611\",\"lang\":\"polyglot\",\"ts\":1792454400000,\"ttl\":6,\"body\":{\"text\":\"Peer-to-Peer for all.\"},\"sig\":\"278c381e5f2ab387f87b7b829fabb6b3\"}";
    uint8_t nonce[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    auto frame = Protocol::encodeFrame(ATP_PKT_MSG, envJson, true, netKey, nonce);
    auto decoded = Protocol::decodeFrame(frame, netKey);
    assert(decoded.envelope_json == envJson);

    std::cout << "{\"status\":\"ok\",\"lang\":\"cpp\",\"peer_a\":\"" << peerA
              << "\",\"peer_b\":\"" << peerB << "\",\"xor_distance\":\"" << dist << "\"}" << std::endl;
    return 0;
}

int main(int argc, char** argv) {
    std::string name = "cpp-peer";
    std::string connectTarget;
    std::string sendText;
    std::string key = "advancetether-default-key";
    int port = 0;
    bool selfTest = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--self-test") == 0) selfTest = true;
        else if (std::strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
        else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (std::strcmp(argv[i], "--connect") == 0 && i + 1 < argc) connectTarget = argv[++i];
        else if (std::strcmp(argv[i], "--send") == 0 && i + 1 < argc) sendText = argv[++i];
        else if (std::strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
    }

    if (selfTest) {
        return runSelfTest();
    }

    Node node(name, key, true);
    if (!connectTarget.empty()) {
        auto colon = connectTarget.rfind(':');
        if (colon == std::string::npos) return 1;
        std::string host = connectTarget.substr(0, colon);
        int remotePort = std::stoi(connectTarget.substr(colon + 1));
        std::string remoteId, replyJson;
        if (!node.connectAndExchange(host, remotePort, sendText, remoteId, replyJson)) {
            return 1;
        }
        std::cout << "{\"event\":\"peer_connected\",\"node\":\"" << node.peerId()
                  << "\",\"peer\":\"" << remoteId << "\",\"lang\":\"cpp\"}" << std::endl;
        if (!replyJson.empty()) {
            std::cout << "{\"event\":\"message\",\"node\":\"" << node.peerId()
                      << "\",\"raw\":" << replyJson << "}" << std::endl;
        }
        return 0;
    }

    int boundPort = node.listenOn(port);
    std::cout << "{\"event\":\"listening\",\"peer_id\":\"" << node.peerId()
              << "\",\"name\":\"" << node.name()
              << "\",\"lang\":\"cpp\",\"host\":\"127.0.0.1\",\"port\":" << boundPort << "}" << std::endl;
    node.serveSingleClient();
    return 0;
}
