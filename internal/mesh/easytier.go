package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Runner executes a command and returns its stdout; injectable for tests.
type Runner func(bin string, args ...string) ([]byte, error)

func execRunner(bin string, args ...string) ([]byte, error) {
	return exec.Command(bin, args...).Output()
}

// CLI wraps easytier-cli invocations. Field names were pinned against
// easytier v2.6.4 (`-o json`); parsing stays defensive because the schema is
// not a stable API: unknown fields are ignored and rows missing an overlay
// IP are skipped.
type CLI struct {
	Bin    string // easytier-cli path; derived from easytier-core path by callers
	Portal string // RPC portal, e.g. 127.0.0.1:15888
	Run    Runner // nil means real exec
}

func (c CLI) run(sub string) ([]byte, error) {
	run := c.Run
	if run == nil {
		run = execRunner
	}
	args := []string{}
	if c.Portal != "" {
		args = append(args, "-p", c.Portal)
	}
	args = append(args, "-o", "json", sub)
	out, err := run(c.Bin, args...)
	if err != nil {
		return nil, fmt.Errorf("mesh: easytier-cli %s: %w", sub, err)
	}
	return out, nil
}

// OverlayPeer is a live easytier peer with an overlay address.
type OverlayPeer struct {
	Hostname  string
	IPv4      string
	Relay     bool // false = direct p2p connection
	LatencyMs float64
}

type peerRow struct {
	IPv4     string `json:"ipv4"`
	Hostname string `json:"hostname"`
	Cost     string `json:"cost"`
	LatMs    string `json:"lat_ms"`
}

// Peers lists reachable overlay peers, excluding this node's own row and
// peers without an overlay IP (e.g. public shared rendezvous nodes).
func (c CLI) Peers() ([]OverlayPeer, error) {
	out, err := c.run("peer")
	if err != nil {
		return nil, err
	}
	var rows []peerRow
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("mesh: parse easytier peer table: %w", err)
	}
	var peers []OverlayPeer
	for _, r := range rows {
		if r.IPv4 == "" || strings.EqualFold(r.Cost, "local") {
			continue
		}
		lat, _ := strconv.ParseFloat(r.LatMs, 64)
		peers = append(peers, OverlayPeer{
			Hostname:  r.Hostname,
			IPv4:      strings.TrimSuffix(r.IPv4, "/24"),
			Relay:     !strings.EqualFold(r.Cost, "p2p"),
			LatencyMs: lat,
		})
	}
	return peers, nil
}

// NodeIP returns this node's overlay IPv4 (bare, CIDR suffix stripped).
func (c CLI) NodeIP() (string, error) {
	out, err := c.run("node")
	if err != nil {
		return "", err
	}
	var node struct {
		IPv4Addr string `json:"ipv4_addr"`
	}
	if err := json.Unmarshal(out, &node); err != nil {
		return "", fmt.Errorf("mesh: parse easytier node info: %w", err)
	}
	ip, _, _ := strings.Cut(node.IPv4Addr, "/")
	if ip == "" {
		return "", errors.New("mesh: easytier node has no overlay IPv4 yet")
	}
	return ip, nil
}

// Connector is one configured rendezvous/relay peer and its dial state.
type Connector struct {
	URL    string
	Status string // connected | disconnected | connecting | unknown
}

// connectorStatusNames indexes easytier's ConnectorStatus proto enum
// (v2.6.4: CONNECTED=0, DISCONNECTED=1, CONNECTING=2).
var connectorStatusNames = []string{"connected", "disconnected", "connecting"}

// Connectors lists the configured rendezvous peers with their live dial
// status — the first thing to look at when the overlay won't form.
func (c CLI) Connectors() ([]Connector, error) {
	out, err := c.run("connector")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		URL struct {
			URL string `json:"url"`
		} `json:"url"`
		Status int `json:"status"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("mesh: parse easytier connector table: %w", err)
	}
	var conns []Connector
	for _, r := range rows {
		if r.URL.URL == "" {
			continue
		}
		status := "unknown"
		if r.Status >= 0 && r.Status < len(connectorStatusNames) {
			status = connectorStatusNames[r.Status]
		}
		conns = append(conns, Connector{URL: r.URL.URL, Status: status})
	}
	return conns, nil
}

// NATInfo is the node's STUN-detected NAT classification: the "will
// hole-punching work?" signal. PublicIPs is what the world sees this router
// as — useful for spotting CGNAT (public IP differs from the wan address).
type NATInfo struct {
	UDPNatType string
	TCPNatType string
	PublicIPs  []string
}

// natTypeNames indexes easytier's NatType proto enum (v2.6.4). Symmetric and
// worse mean punching usually fails and traffic falls back to the relay.
var natTypeNames = []string{
	"Unknown", "OpenInternet", "NoPAT", "FullCone", "Restricted",
	"PortRestricted", "Symmetric", "SymUdpFirewall", "SymmetricEasyInc", "SymmetricEasyDec",
}

// NAT returns the node's STUN classification from the node info.
func (c CLI) NAT() (NATInfo, error) {
	out, err := c.run("node")
	if err != nil {
		return NATInfo{}, err
	}
	var node struct {
		StunInfo struct {
			UDPNatType int      `json:"udp_nat_type"`
			TCPNatType int      `json:"tcp_nat_type"`
			PublicIP   []string `json:"public_ip"`
		} `json:"stun_info"`
	}
	if err := json.Unmarshal(out, &node); err != nil {
		return NATInfo{}, fmt.Errorf("mesh: parse easytier node info: %w", err)
	}
	name := func(i int) string {
		if i >= 0 && i < len(natTypeNames) {
			return natTypeNames[i]
		}
		return "Unknown"
	}
	return NATInfo{
		UDPNatType: name(node.StunInfo.UDPNatType),
		TCPNatType: name(node.StunInfo.TCPNatType),
		PublicIPs:  node.StunInfo.PublicIP,
	}, nil
}
