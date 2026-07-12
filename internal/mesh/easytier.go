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
