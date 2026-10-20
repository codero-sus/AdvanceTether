use advancetether::{
    encode_frame, generate_peer_id, sign_envelope_fields, to_hex, xor_distance, AdvanceTetherNode,
    PacketType,
};
use std::env;

fn run_self_test() -> i32 {
    let net_key = "advancetether-universal-key-2026";
    let peer_a = generate_peer_id("seed-alpha");
    let peer_b = generate_peer_id("seed-beta");
    assert_eq!(peer_a, "atp_ba316cd7abc9b7dc");
    assert_eq!(peer_b, "atp_d9c30acfd5686611");

    let dist = xor_distance(&peer_a, &peer_b);
    assert_eq!(dist, 7201931009508626893u64);

    let sig = sign_envelope_fields(
        "msg_0123456789abcdef",
        "MSG",
        &peer_a,
        &peer_b,
        1792454400000i64,
        net_key,
    );
    assert_eq!(sig, "278c381e5f2ab387f87b7b829fabb6b3");

    let env_json = "{\"v\":1,\"id\":\"msg_0123456789abcdef\",\"type\":\"MSG\",\"from\":\"atp_ba316cd7abc9b7dc\",\"to\":\"atp_d9c30acfd5686611\",\"lang\":\"polyglot\",\"ts\":1792454400000,\"ttl\":6,\"body\":{\"text\":\"Peer-to-Peer for all.\"},\"sig\":\"278c381e5f2ab387f87b7b829fabb6b3\"}";
    let nonce: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let frame = encode_frame(PacketType::Msg, env_json, true, net_key, &nonce);
    assert_eq!(&frame[0..4], b"AT2P");

    println!(
        "{{\"status\":\"ok\",\"lang\":\"rust\",\"peer_a\":\"{}\",\"peer_b\":\"{}\",\"xor_distance\":\"{}\",\"frame_hex_prefix\":\"{}\"}}",
        peer_a,
        peer_b,
        dist,
        to_hex(&frame[0..12])
    );
    0
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--self-test") {
        std::process::exit(run_self_test());
    }

    let node = AdvanceTetherNode::new("rust-peer", "advancetether-default-key");
    let (_listener, port) = node.bind_listener("127.0.0.1", 0).expect("bind failed");
    println!(
        "{{\"event\":\"listening\",\"peer_id\":\"{}\",\"name\":\"{}\",\"lang\":\"rust\",\"host\":\"127.0.0.1\",\"port\":{}}}",
        node.peer_id, node.name, port
    );
}
