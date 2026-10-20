package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	atp "github.com/codero-sus/AdvanceTether/sdks/go"
)

func runSelfTest() int {
	netKey := "advancetether-universal-key-2026"
	peerA := atp.GeneratePeerID("seed-alpha")
	peerB := atp.GeneratePeerID("seed-beta")
	if peerA != "atp_ba316cd7abc9b7dc" || peerB != "atp_d9c30acfd5686611" {
		fmt.Fprintf(os.Stderr, "Go peer_id mismatch: %s %s\n", peerA, peerB)
		return 1
	}
	dist := atp.XORDistance(peerA, peerB)
	if dist != 7201931009508626893 {
		fmt.Fprintf(os.Stderr, "Go XOR distance mismatch: %d\n", dist)
		return 1
	}
	env := &atp.Envelope{
		V:    1,
		ID:   "msg_0123456789abcdef",
		Type: "MSG",
		From: peerA,
		To:   peerB,
		Lang: "polyglot",
		Ts:   1792454400000,
		TTL:  6,
		Body: map[string]interface{}{"text": "Peer-to-Peer for all."},
	}
	env.Sig = atp.SignEnvelope(env, netKey)
	if env.Sig != "278c381e5f2ab387f87b7b829fabb6b3" {
		fmt.Fprintf(os.Stderr, "Go sig mismatch: %s\n", env.Sig)
		return 1
	}
	frame, err := atp.EncodeFrame(atp.PktMsg, env, true, netKey, "000102030405060708090a0b0c0d0e0f")
	if err != nil {
		return 1
	}
	_, _, dec, err := atp.DecodeFrame(frame, netKey)
	if err != nil || dec.Body["text"] != "Peer-to-Peer for all." {
		return 1
	}
	fmt.Printf("{\"status\":\"ok\",\"lang\":\"go\",\"peer_a\":\"%s\",\"peer_b\":\"%s\",\"frame_len\":%d,\"magic\":\"%s\"}\n",
		peerA, peerB, len(frame), hex.EncodeToString(frame[:4]))
	return 0
}

func main() {
	selfTest := flag.Bool("self-test", false, "Run ATP/1.0 test vector verification")
	name := flag.String("name", "go-peer", "Node name")
	host := flag.String("host", "127.0.0.1", "Bind host")
	port := flag.Int("port", 0, "Bind port")
	key := flag.String("key", "advancetether-default-key", "Shared network key")
	flag.Parse()

	if *selfTest {
		os.Exit(runSelfTest())
	}

	node := atp.NewNode(*name, *host, *port, *key)
	boundPort, err := node.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("{\"event\":\"listening\",\"peer_id\":\"%s\",\"name\":\"%s\",\"lang\":\"go\",\"host\":\"%s\",\"port\":%d}\n",
		node.PeerID, node.Name, *host, boundPort)
	select {}
}
