package mesh

import (
	"errors"
	"strings"
	"testing"
)

// Fixtures mirror easytier v2.6.4 `-o json` output (all row fields are
// strings; the local node appears in the peer table with cost "Local").

const nodeJSON = `{
  "peer_id": 123456,
  "ipv4_addr": "10.126.126.1/24",
  "proxy_cidrs": [],
  "hostname": "router-alpha",
  "stun_info": {"udp_nat_type": 6, "tcp_nat_type": 0, "public_ip": ["1.2.3.4"]},
  "inst_id": "abc",
  "listeners": ["tcp://0.0.0.0:11010"],
  "version": "2.6.4"
}`

const peerJSON = `[
  {"cidr": "10.126.126.1/24", "ipv4": "10.126.126.1", "hostname": "router-alpha", "cost": "Local", "lat_ms": "-", "loss_rate": "-", "rx_bytes": "-", "tx_bytes": "-", "tunnel_proto": "-", "nat_type": "PortRestricted", "id": "123456", "version": "2.6.4"},
  {"cidr": "10.126.126.2/24", "ipv4": "10.126.126.2", "hostname": "router-beta", "cost": "p2p", "lat_ms": "12.34", "loss_rate": "0.0%", "rx_bytes": "1.2 kB", "tx_bytes": "3.4 kB", "tunnel_proto": "udp", "nat_type": "PortRestricted", "id": "654321", "version": "2.6.4"},
  {"cidr": "", "ipv4": "", "hostname": "public-node", "cost": "p2p", "lat_ms": "45.00", "loss_rate": "0.0%", "rx_bytes": "-", "tx_bytes": "-", "tunnel_proto": "tcp", "nat_type": "Unknown", "id": "111", "version": "2.6.4"},
  {"cidr": "10.126.126.3/24", "ipv4": "10.126.126.3", "hostname": "router-gamma", "cost": "relay(2)", "lat_ms": "80.10", "loss_rate": "0.0%", "rx_bytes": "-", "tx_bytes": "-", "tunnel_proto": "udp", "nat_type": "Symmetric", "id": "222", "version": "2.6.4"}
]`

func fakeRunner(t *testing.T, outputs map[string]string) Runner {
	t.Helper()
	return func(bin string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		for key, out := range outputs {
			if strings.HasSuffix(joined, key) {
				return []byte(out), nil
			}
		}
		return nil, errors.New("unexpected invocation: " + bin + " " + joined)
	}
}

func TestNodeIP(t *testing.T) {
	cli := CLI{Bin: "/usr/bin/easytier-cli", Portal: "127.0.0.1:15888", Run: fakeRunner(t, map[string]string{"node": nodeJSON})}
	ip, err := cli.NodeIP()
	if err != nil {
		t.Fatalf("NodeIP: %v", err)
	}
	if ip != "10.126.126.1" {
		t.Fatalf("NodeIP = %q, want bare IP without CIDR suffix", ip)
	}
}

func TestNodeIPUnset(t *testing.T) {
	cli := CLI{Run: fakeRunner(t, map[string]string{"node": `{"peer_id": 1, "ipv4_addr": "", "hostname": "x"}`})}
	if _, err := cli.NodeIP(); err == nil {
		t.Fatal("expected error for node without overlay IP")
	}
}

func TestPeersSkipsSelfAndIPless(t *testing.T) {
	cli := CLI{Run: fakeRunner(t, map[string]string{"peer": peerJSON})}
	peers, err := cli.Peers()
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2 (self and IP-less shared node skipped): %#v", len(peers), peers)
	}
	beta := peers[0]
	if beta.Hostname != "router-beta" || beta.IPv4 != "10.126.126.2" || beta.Relay {
		t.Fatalf("unexpected first peer: %#v", beta)
	}
	if beta.LatencyMs != 12.34 {
		t.Fatalf("latency parse: %v", beta.LatencyMs)
	}
	gamma := peers[1]
	if !gamma.Relay {
		t.Fatalf("relay(2) peer not flagged as relay: %#v", gamma)
	}
}

func TestPeersRunnerError(t *testing.T) {
	cli := CLI{Run: func(string, ...string) ([]byte, error) { return nil, errors.New("boom") }}
	if _, err := cli.Peers(); err == nil {
		t.Fatal("runner error swallowed")
	}
}

func TestPeersGarbageJSON(t *testing.T) {
	cli := CLI{Run: fakeRunner(t, map[string]string{"peer": "not json"})}
	if _, err := cli.Peers(); err == nil {
		t.Fatal("garbage JSON accepted")
	}
}
