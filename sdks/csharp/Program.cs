using System;

namespace AdvanceTether
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            foreach (var arg in args)
            {
                if (arg == "--self-test")
                {
                    const string netKey = "advancetether-universal-key-2026";
                    string peerA = AdvanceTetherNode.GeneratePeerId("seed-alpha");
                    string peerB = AdvanceTetherNode.GeneratePeerId("seed-beta");
                    ulong dist = AdvanceTetherNode.XorDistance(peerA, peerB);
                    string sig = AdvanceTetherNode.SignEnvelopeFields("msg_0123456789abcdef", "MSG", peerA, peerB, 1792454400000L, netKey);

                    if (peerA != "atp_ba316cd7abc9b7dc" || sig != "278c381e5f2ab387f87b7b829fabb6b3" || dist != 7201931009508626893UL)
                    {
                        Console.Error.WriteLine("C# test vector mismatch");
                        return 1;
                    }

                    Console.WriteLine($"{{\"status\":\"ok\",\"lang\":\"csharp\",\"peer_a\":\"{peerA}\",\"peer_b\":\"{peerB}\",\"xor_distance\":\"{dist}\"}}");
                    return 0;
                }
            }

            var node = new AdvanceTetherNode("csharp-peer");
            int port = node.StartListener(0);
            Console.WriteLine($"{{\"event\":\"listening\",\"peer_id\":\"{node.PeerId}\",\"lang\":\"csharp\",\"port\":{port}}}");
            node.StopListener();
            return 0;
        }
    }
}
