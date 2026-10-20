#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once __DIR__ . "/../src/AdvanceTetherNode.php";

use AdvanceTether\AdvanceTetherNode;

if (in_array("--self-test", $argv, true)) {
    $netKey = "advancetether-universal-key-2026";
    $peerA = AdvanceTetherNode::generatePeerId("seed-alpha");
    $peerB = AdvanceTetherNode::generatePeerId("seed-beta");
    $env = [
        "v" => 1,
        "id" => "msg_0123456789abcdef",
        "type" => "MSG",
        "from" => $peerA,
        "to" => $peerB,
        "lang" => "polyglot",
        "ts" => 1792454400000,
        "ttl" => 6,
        "body" => ["text" => "Peer-to-Peer for all."],
    ];
    $env["sig"] = AdvanceTetherNode::signEnvelope($env, $netKey);
    if ($peerA !== "atp_ba316cd7abc9b7dc" || $env["sig"] !== "278c381e5f2ab387f87b7b829fabb6b3") {
        fwrite(STDERR, "PHP test vector mismatch\n");
        exit(1);
    }
    echo json_encode([
        "status" => "ok",
        "lang" => "php",
        "peer_a" => $peerA,
        "peer_b" => $peerB,
        "sig" => $env["sig"],
    ]) . PHP_EOL;
    exit(0);
}

$node = new AdvanceTetherNode();
echo json_encode(["event" => "initialized", "peer_id" => $node->peerId, "lang" => "php"]) . PHP_EOL;
