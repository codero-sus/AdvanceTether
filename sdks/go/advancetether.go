// Package advancetether implements the AdvanceTether Protocol v1.0 (ATP/1.0) in Go.
// Peer-to-Peer for All Languages — Messaging, DHT, Pub/Sub, File Transfer & Network Tunneling.
package advancetether

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Magic         = "AT2P"
	Version       = 1
	HeaderSize    = 12
	MaxPayload    = 16 * 1024 * 1024
	FlagEncrypted = 0x01
)

const (
	PktHello       uint8 = 0x01
	PktHelloAck    uint8 = 0x02
	PktPing        uint8 = 0x03
	PktPong        uint8 = 0x04
	PktDiscover    uint8 = 0x05
	PktPeerList    uint8 = 0x06
	PktDHTPut      uint8 = 0x07
	PktDHTGet      uint8 = 0x08
	PktDHTRes      uint8 = 0x09
	PktMsg         uint8 = 0x0A
	PktPubSubSub   uint8 = 0x0B
	PktPubSubPub   uint8 = 0x0C
	PktFileOffer   uint8 = 0x0D
	PktFileChunk   uint8 = 0x0E
	PktFileAck     uint8 = 0x0F
	PktTunnelOpen  uint8 = 0x10
	PktTunnelData  uint8 = 0x11
	PktTunnelClose uint8 = 0x12
	PktHolePunch   uint8 = 0x13
)

var PacketNames = map[uint8]string{
	PktHello:       "HELLO",
	PktHelloAck:    "HELLO_ACK",
	PktPing:        "PING",
	PktPong:        "PONG",
	PktDiscover:    "DISCOVER",
	PktPeerList:    "PEER_LIST",
	PktDHTPut:      "DHT_PUT",
	PktDHTGet:      "DHT_GET",
	PktDHTRes:      "DHT_RES",
	PktMsg:         "MSG",
	PktPubSubSub:   "PUBSUB_SUB",
	PktPubSubPub:   "PUBSUB_PUB",
	PktFileOffer:   "FILE_OFFER",
	PktFileChunk:   "FILE_CHUNK",
	PktFileAck:     "FILE_ACK",
	PktTunnelOpen:  "TUNNEL_OPEN",
	PktTunnelData:  "TUNNEL_DATA",
	PktTunnelClose: "TUNNEL_CLOSE",
	PktHolePunch:   "HOLE_PUNCH",
}

type Envelope struct {
	V    int                    `json:"v"`
	ID   string                 `json:"id"`
	Type string                 `json:"type"`
	From string                 `json:"from"`
	To   string                 `json:"to"`
	Lang string                 `json:"lang"`
	Ts   int64                  `json:"ts"`
	TTL  int                    `json:"ttl"`
	Body map[string]interface{} `json:"body"`
	Sig  string                 `json:"sig"`
}

type encryptedEnvelope struct {
	Enc        string `json:"enc"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func Sha256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func Sha256Hex(data []byte) string {
	return hex.EncodeToString(Sha256Bytes(data))
}

func GeneratePeerID(seed string) string {
	if seed == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		seed = hex.EncodeToString(b)
	}
	return "atp_" + Sha256Hex([]byte(seed))[:16]
}

func DeriveKeys(networkKey string) (kEnc []byte, kMac []byte) {
	kEnc = Sha256Bytes([]byte("ATP_ENC:" + networkKey))
	kMac = Sha256Bytes([]byte("ATP_MAC:" + networkKey))
	return kEnc, kMac
}

func keystreamXOR(data, kEnc, nonce []byte) []byte {
	out := make([]byte, len(data))
	blocks := (len(data) + 31) / 32
	var counterBuf [4]byte
	for c := 0; c < blocks; c++ {
		binary.BigEndian.PutUint32(counterBuf[:], uint32(c))
		in := make([]byte, 0, 52)
		in = append(in, kEnc...)
		in = append(in, nonce...)
		in = append(in, counterBuf[:]...)
		stream := Sha256Bytes(in)
		start := c * 32
		end := start + 32
		if end > len(data) {
			end = len(data)
		}
		for i := start; i < end; i++ {
			out[i] = data[i] ^ stream[i-start]
		}
	}
	return out
}

func EncryptPayload(plaintext []byte, networkKey string, nonceHex string) ([]byte, error) {
	kEnc, kMac := DeriveKeys(networkKey)
	var nonce []byte
	var err error
	if nonceHex != "" {
		nonce, err = hex.DecodeString(nonceHex)
		if err != nil {
			return nil, err
		}
	} else {
		nonce = make([]byte, 16)
		_, _ = rand.Read(nonce)
		nonceHex = hex.EncodeToString(nonce)
	}
	ciphertext := keystreamXOR(plaintext, kEnc, nonce)
	mac := hmac.New(sha256.New, kMac)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := hex.EncodeToString(mac.Sum(nil))

	env := encryptedEnvelope{
		Enc:        "ATP-SHA256-CTR-HMAC",
		Nonce:      nonceHex,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Tag:        tag,
	}
	return json.Marshal(env)
}

func DecryptPayload(encryptedJSON []byte, networkKey string) ([]byte, error) {
	kEnc, kMac := DeriveKeys(networkKey)
	var env encryptedEnvelope
	if err := json.Unmarshal(encryptedJSON, &env); err != nil {
		return nil, err
	}
	if env.Enc != "ATP-SHA256-CTR-HMAC" {
		return nil, fmt.Errorf("unsupported encryption scheme: %s", env.Enc)
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, kMac)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedTag := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedTag), []byte(env.Tag)) {
		return nil, errors.New("ATP HMAC authentication tag mismatch")
	}
	return keystreamXOR(ciphertext, kEnc, nonce), nil
}

func SignEnvelope(env *Envelope, networkKey string) string {
	_, kMac := DeriveKeys(networkKey)
	canonical := fmt.Sprintf("%s:%s:%s:%s:%d", env.ID, env.Type, env.From, env.To, env.Ts)
	mac := hmac.New(sha256.New, kMac)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func VerifyEnvelope(env *Envelope, networkKey string) bool {
	if env == nil || env.Sig == "" {
		return false
	}
	expected := SignEnvelope(env, networkKey)
	return hmac.Equal([]byte(expected), []byte(env.Sig))
}

func IDToUint64(peerID string) uint64 {
	clean := strings.TrimPrefix(peerID, "atp_")
	if len(clean) < 16 {
		clean = clean + strings.Repeat("0", 16-len(clean))
	} else if len(clean) > 16 {
		clean = clean[:16]
	}
	v, err := strconv.ParseUint(clean, 16, 64)
	if err != nil {
		digest := Sha256Hex([]byte(peerID))[:16]
		v, _ = strconv.ParseUint(digest, 16, 64)
	}
	return v
}

func XORDistance(peerA, peerB string) uint64 {
	return IDToUint64(peerA) ^ IDToUint64(peerB)
}

func EncodeFrame(msgType uint8, env *Envelope, encrypt bool, networkKey string, nonceHex string) ([]byte, error) {
	rawJSON, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	var flags uint8
	payload := rawJSON
	if encrypt {
		flags |= FlagEncrypted
		payload, err = EncryptPayload(rawJSON, networkKey, nonceHex)
		if err != nil {
			return nil, err
		}
	}
	buf := bytes.NewBuffer(make([]byte, 0, HeaderSize+len(payload)))
	buf.WriteString(Magic)
	buf.WriteByte(Version)
	buf.WriteByte(flags)
	buf.WriteByte(msgType)
	buf.WriteByte(0)
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	buf.Write(lenBytes[:])
	buf.Write(payload)
	return buf.Bytes(), nil
}

func DecodeFrame(frame []byte, networkKey string) (uint8, uint8, *Envelope, error) {
	if len(frame) < HeaderSize {
		return 0, 0, nil, errors.New("frame shorter than header")
	}
	if string(frame[0:4]) != Magic {
		return 0, 0, nil, errors.New("invalid ATP magic header")
	}
	if frame[4] != Version {
		return 0, 0, nil, fmt.Errorf("unsupported version: %d", frame[4])
	}
	flags := frame[5]
	msgType := frame[6]
	length := binary.BigEndian.Uint32(frame[8:12])
	if uint32(len(frame)) < HeaderSize+length {
		return 0, 0, nil, errors.New("truncated ATP frame")
	}
	payload := frame[HeaderSize : HeaderSize+length]
	var err error
	if flags&FlagEncrypted != 0 {
		payload, err = DecryptPayload(payload, networkKey)
		if err != nil {
			return 0, 0, nil, err
		}
	}
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return 0, 0, nil, err
	}
	return msgType, flags, &env, nil
}

func ReadFrameFromConn(conn net.Conn, networkKey string) (uint8, uint8, *Envelope, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, 0, nil, err
	}
	if string(header[0:4]) != Magic {
		return 0, 0, nil, errors.New("invalid ATP magic")
	}
	length := binary.BigEndian.Uint32(header[8:12])
	if length > MaxPayload {
		return 0, 0, nil, errors.New("payload too large")
	}
	full := make([]byte, HeaderSize+length)
	copy(full[0:HeaderSize], header)
	if _, err := io.ReadFull(conn, full[HeaderSize:]); err != nil {
		return 0, 0, nil, err
	}
	return DecodeFrame(full, networkKey)
}

type PeerEntry struct {
	PeerID      string `json:"peer_id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Lang        string `json:"lang"`
	Name        string `json:"name"`
	XORDistance uint64 `json:"xor_distance"`
	conn        net.Conn
}

type Node struct {
	Name        string
	Lang        string
	Host        string
	Port        int
	NetworkKey  string
	PeerID      string
	Encrypt     bool
	DownloadDir string

	mu            sync.RWMutex
	listener      net.Listener
	peers         map[string]*PeerEntry
	dhtStore      map[string]interface{}
	subscriptions map[string]bool
	seenMsgs      map[string]bool
}

func NewNode(name, host string, port int, networkKey string) *Node {
	if networkKey == "" {
		networkKey = "advancetether-default-key"
	}
	dl := "/tmp/advancetether_downloads"
	_ = os.MkdirAll(dl, 0o755)
	return &Node{
		Name:          name,
		Lang:          "go",
		Host:          host,
		Port:          port,
		NetworkKey:    networkKey,
		PeerID:        GeneratePeerID(fmt.Sprintf("go:%s:%d", name, time.Now().UnixNano())),
		Encrypt:       true,
		DownloadDir:   dl,
		peers:         make(map[string]*PeerEntry),
		dhtStore:      make(map[string]interface{}),
		subscriptions: map[string]bool{"global": true},
		seenMsgs:      make(map[string]bool),
	}
}

func (n *Node) Start() (int, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", n.Host, n.Port))
	if err != nil {
		return 0, err
	}
	n.listener = ln
	n.Port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go n.handleConn(conn)
		}
	}()
	return n.Port, nil
}

func (n *Node) Stop() {
	if n.listener != nil {
		_ = n.listener.Close()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range n.peers {
		if p.conn != nil {
			_ = p.conn.Close()
		}
	}
}

func (n *Node) MakeEnvelope(msgType uint8, toPeer string, body map[string]interface{}) *Envelope {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	env := &Envelope{
		V:    Version,
		ID:   "msg_" + hex.EncodeToString(b),
		Type: PacketNames[msgType],
		From: n.PeerID,
		To:   toPeer,
		Lang: n.Lang,
		Ts:   time.Now().UnixMilli(),
		TTL:  6,
		Body: body,
	}
	env.Sig = SignEnvelope(env, n.NetworkKey)
	return env
}

func (n *Node) Connect(host string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", err
	}
	hello := n.MakeEnvelope(PktHello, "*", map[string]interface{}{
		"peer_id": n.PeerID,
		"name":    n.Name,
		"lang":    n.Lang,
		"host":    n.Host,
		"port":    n.Port,
	})
	frame, err := EncodeFrame(PktHello, hello, n.Encrypt, n.NetworkKey, "")
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	if _, err := conn.Write(frame); err != nil {
		_ = conn.Close()
		return "", err
	}
	_, _, ackEnv, err := ReadFrameFromConn(conn, n.NetworkKey)
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	remoteID := ackEnv.From
	n.mu.Lock()
	n.peers[remoteID] = &PeerEntry{
		PeerID:      remoteID,
		Host:        host,
		Port:        port,
		Lang:        ackEnv.Lang,
		Name:        remoteID,
		XORDistance: XORDistance(n.PeerID, remoteID),
		conn:        conn,
	}
	n.mu.Unlock()
	go n.handleConn(conn)
	return remoteID, nil
}

func (n *Node) SendMessage(peerID, text, rpc string) error {
	n.mu.RLock()
	peer, ok := n.peers[peerID]
	n.mu.RUnlock()
	if !ok || peer.conn == nil {
		return errors.New("peer not connected")
	}
	body := map[string]interface{}{"text": text}
	if rpc != "" {
		body["rpc"] = rpc
	}
	env := n.MakeEnvelope(PktMsg, peerID, body)
	frame, err := EncodeFrame(PktMsg, env, n.Encrypt, n.NetworkKey, "")
	if err != nil {
		return err
	}
	_, err = peer.conn.Write(frame)
	return err
}

func (n *Node) ClosestPeers(targetID string, count int) []PeerEntry {
	n.mu.RLock()
	defer n.mu.RUnlock()
	list := make([]PeerEntry, 0, len(n.peers))
	for _, p := range n.peers {
		cp := *p
		cp.XORDistance = XORDistance(targetID, p.PeerID)
		list = append(list, cp)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].XORDistance < list[j].XORDistance
	})
	if len(list) > count {
		list = list[:count]
	}
	return list
}

func (n *Node) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		msgType, _, env, err := ReadFrameFromConn(conn, n.NetworkKey)
		if err != nil {
			return
		}
		if !VerifyEnvelope(env, n.NetworkKey) {
			continue
		}
		switch msgType {
		case PktHello:
			n.mu.Lock()
			n.peers[env.From] = &PeerEntry{
				PeerID:      env.From,
				Host:        "127.0.0.1",
				Port:        0,
				Lang:        env.Lang,
				Name:        env.From,
				XORDistance: XORDistance(n.PeerID, env.From),
				conn:        conn,
			}
			n.mu.Unlock()
			ack := n.MakeEnvelope(PktHelloAck, env.From, map[string]interface{}{
				"peer_id": n.PeerID,
				"name":    n.Name,
				"lang":    n.Lang,
				"port":    n.Port,
			})
			if f, err := EncodeFrame(PktHelloAck, ack, n.Encrypt, n.NetworkKey, ""); err == nil {
				_, _ = conn.Write(f)
			}
		case PktDHTPut:
			if k, ok := env.Body["key"].(string); ok {
				n.mu.Lock()
				n.dhtStore[k] = env.Body["value"]
				n.mu.Unlock()
			}
		case PktMsg:
			if env.Body["rpc"] == "echo" {
				reply := n.MakeEnvelope(PktMsg, env.From, map[string]interface{}{
					"text":      fmt.Sprintf("Echo from %s (go): %v", n.Name, env.Body["text"]),
					"rpc_reply": env.ID,
				})
				if f, err := EncodeFrame(PktMsg, reply, n.Encrypt, n.NetworkKey, ""); err == nil {
					_, _ = conn.Write(f)
				}
			}
		case PktFileChunk:
			if fn, ok := env.Body["filename"].(string); ok {
				if b64, ok := env.Body["data_b64"].(string); ok {
					if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
						_ = os.WriteFile(filepath.Join(n.DownloadDir, filepath.Base(fn)), raw, 0o644)
					}
				}
			}
		}
	}
}
