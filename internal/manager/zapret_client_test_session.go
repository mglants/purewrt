package manager

// The client tester owns temporary rules only. Timed nft memberships make its
// bypass and route mark expire even if the worker is killed without cleanup.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

const clientTestName = "purewrt_client_test"
const clientTestMark = "0x08000000"

// nfqws skips packets with ANY bit of its generated-packet mark set. Keep
// the client routing bit disjoint or every real client packet is ignored.
const clientTestFakeMark = "0x10000000"
const clientTestTable = "9908"
const clientTestQueue = "9908"
const clientTestSeconds = 300

type ZapretClientOptions struct{ IP, MAC, Interface, Candidate, Extra, Manual string }
type ZapretClientState struct {
	Manual       string `json:"manual,omitempty"`
	ProcessGroup int    `json:"process_group,omitempty"`
	Phase        string `json:"phase,omitempty"`
	Running      bool   `json:"running"`
	IP           string `json:"ip,omitempty"`
	Interface    string `json:"interface,omitempty"`
	Candidate    string `json:"candidate,omitempty"`
	Extra        string `json:"extra,omitempty"`
	Expires      int64  `json:"expires,omitempty"`
	Error        string `json:"error,omitempty"`
	Counters     string `json:"counters,omitempty"`
}

func clientTestPath(suffix string) string { return "/tmp/" + clientTestName + suffix }
func clientTestSave(s ZapretClientState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return system.AtomicWrite(clientTestPath(".json"), b, 0600)
}
func (m Manager) ZapretClientStatus() ZapretClientState {
	var s ZapretClientState
	b, e := os.ReadFile(clientTestPath(".json"))
	if e == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Running {
		lock, e := system.TryAcquire(clientTestPath(".lock"))
		if e == nil {
			lock.Close()
			s.Running = false
			s.Error = "Test worker stopped; temporary memberships expire automatically"
		}
		if time.Now().Unix() >= s.Expires {
			s.Running = false
		}
		if s.Running {
			s.Counters, _ = (system.Runner{}).Run("nft", "list", "counters", "table", "inet", clientTestName)
		}
	}
	return s
}
func (m Manager) ZapretClientStop() error {
	if err := system.AtomicWrite(clientTestPath(".stop"), []byte("stop\n"), 0600); err != nil {
		return err
	}
	// An interrupted worker may have left inert rules after their membership expired.
	lock, err := system.TryAcquire(clientTestPath(".lock"))
	if errors.Is(err, system.ErrLockBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	state := m.ZapretClientStatus()
	if state.ProcessGroup > 1 {
		if cmd, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", state.ProcessGroup)); e == nil && strings.Contains(string(cmd), "purewrt-client-nfq\x00") {
			_ = syscall.Kill(-state.ProcessGroup, syscall.SIGTERM)
		}
	}
	if state.IP == "" {
		return nil
	}
	err = clientTestCleanup(system.Runner{Timeout: 5 * time.Second})
	state.Running = false
	state.Phase = "stopped"
	state.Counters = ""
	state.ProcessGroup = 0
	if err != nil {
		state.Error = err.Error()
	} else {
		state.Error = ""
	}
	return errors.Join(err, clientTestSave(state))
}

func clientTestValidate(o ZapretClientOptions) error {
	ip := net.ParseIP(o.IP)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return fmt.Errorf("select a private IPv4 LAN client")
	}
	mac, e := net.ParseMAC(o.MAC)
	if e != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return fmt.Errorf("select a client with a valid unicast MAC address")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`).MatchString(o.Interface) || len(o.Interface) > 15 {
		return fmt.Errorf("invalid WAN device")
	}
	return nil
}
func clientTestCandidates(o ZapretClientOptions, list config.ZapretCandidateList) ([]config.ZapretCandidate, error) {
	if o.Candidate == "__manual__" {
		if o.Extra != "" {
			return nil, fmt.Errorf("include both protocols in manual parameters using --new")
		}
		c, err := clientManualCandidate(o.Manual)
		if err != nil {
			return nil, err
		}
		return []config.ZapretCandidate{c}, nil
	}
	if o.Manual != "" {
		return nil, fmt.Errorf("manual parameters require manual strategy selection")
	}
	if o.Candidate == "__direct__" {
		if o.Extra != "" {
			return nil, fmt.Errorf("baseline cannot include another strategy")
		}
		return []config.ZapretCandidate{{Name: "__direct__", Protocols: []string{"tcp", "udp"}, Params: "--filter-tcp=1-65535 --filter-udp=1-65535"}}, nil
	}
	var out []config.ZapretCandidate
	for _, name := range []string{o.Candidate, o.Extra} {
		if name == "" {
			continue
		}
		found := false
		for _, c := range list.Candidates {
			if c.Name == name {
				out = append(out, c)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown strategy %q", name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("select a strategy")
	}
	if len(out) == 2 {
		// Combining only disjoint protocols avoids first-profile shadowing.
		if len(out[0].Protocols) != 1 || len(out[1].Protocols) != 1 || out[0].Protocols[0] == out[1].Protocols[0] {
			return nil, fmt.Errorf("combine one TCP-only and one UDP-only candidate")
		}
	}
	for _, c := range out {
		if strings.TrimSpace(c.Params) == "" {
			return nil, fmt.Errorf("empty candidate")
		}
		for _, a := range strings.Fields(c.Params) {
			for _, bad := range []string{"--qnum", "--fwmark", "--daemon", "--pidfile", "--user", "--uid", "--bind-fix", "--lua-init", "--debug"} {
				if strings.HasPrefix(a, bad) {
					return nil, fmt.Errorf("candidate contains process option %s", bad)
				}
			}
		}
	}
	return out, nil
}
func clientTestDefaultRoute(routes, dev string) ([]string, error) {
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		var d, g string
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				d = f[i+1]
			}
			if f[i] == "via" {
				g = f[i+1]
			}
		}
		if d != dev {
			continue
		}
		a := []string{"-4", "route", "add", "table", clientTestTable, "default"}
		if g != "" {
			if net.ParseIP(g).To4() == nil {
				return nil, fmt.Errorf("invalid gateway")
			}
			a = append(a, "via", g)
		}
		a = append(a, "dev", dev)
		if g != "" {
			a = append(a, "onlink")
		}
		return a, nil
	}
	return nil, fmt.Errorf("selected WAN has no IPv4 default route in the main table")
}

func clientTestNFT(o ZapretClientOptions, mask string) string {
	parsedMask, _ := strconv.ParseUint(mask, 0, 32)
	keepMask := fmt.Sprintf("0x%08x", ^uint32(parsedMask))
	// Local destinations retain router DNS, LAN connectivity and existing policy.
	local := "ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } return\n"
	return fmt.Sprintf(`add table inet %[1]s
add set inet %[1]s clients { type ipv4_addr; flags timeout; timeout 300s; elements = { %[2]s }; }
add set inet %[1]s macs { type ether_addr; flags timeout; timeout 300s; elements = { %[3]s }; }
add counter inet %[1]s tcp_out
add counter inet %[1]s udp_out
add chain inet %[1]s route { type filter hook prerouting priority -140; policy accept; }
add rule inet %[1]s route ct direction reply return
add rule inet %[1]s route %[5]s
add rule inet %[1]s route ip saddr @clients meta mark set meta mark & %[6]s | 0x08000000
add chain inet %[1]s guard { type filter hook forward priority -1; policy accept; }
add rule inet %[1]s guard ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } return
add rule inet %[1]s guard meta nfproto ipv6 ether saddr @macs reject with icmpv6 type admin-prohibited
add rule inet %[1]s guard ct direction original ip saddr @clients meta mark & 0x08000000 != 0 oifname != "%[4]s" reject
add chain inet %[1]s post { type filter hook postrouting priority 102; policy accept; }
add rule inet %[1]s post meta mark & 0x10000000 != 0 return
add rule inet %[1]s post ct direction original ct original ip saddr @clients oifname "%[4]s" tcp dport 1-65535 ct original packets 1-20 counter name tcp_out queue num 9908 bypass
add rule inet %[1]s post ct direction original ct original ip saddr @clients oifname "%[4]s" udp dport 1-65535 ct original packets 1-20 counter name udp_out queue num 9908 bypass
add chain inet %[1]s incoming { type filter hook prerouting priority -151; policy accept; }
add rule inet %[1]s incoming ct direction reply ct original ip saddr @clients iifname "%[4]s" meta l4proto { tcp, udp } ct reply packets 1-10 queue num 9908 bypass
add chain inet %[1]s raw { type filter hook output priority -402; policy accept; }
add rule inet %[1]s raw meta mark & 0x10000000 != 0 notrack
add set inet purewrt %[1]s { type ipv4_addr; flags timeout; timeout 300s; elements = { %[2]s }; }
insert rule inet purewrt prerouting ip saddr @%[1]s return comment "%[1]s"
insert rule inet purewrt prerouting ct direction reply ct original ip saddr @%[1]s return comment "%[1]s"
insert rule inet purewrt output_mangle meta mark & 0x10000000 != 0 return comment "%[1]s"
`, clientTestName, o.IP, strings.ToLower(o.MAC), o.Interface, local, keepMask)
}

// Cleanup matches our comment only; never flush a production chain or table.
func clientTestCleanup(r commandRunner) error {
	var errs []error
	if e := clientOffloadCleanup(r); e != nil {
		errs = append(errs, e)
	}
	for _, chain := range []string{"prerouting", "postrouting", "output_mangle"} {
		out, e := r.Run("nft", "-a", "list", "chain", "inet", "purewrt", chain)
		if e != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, `comment "`+clientTestName+`"`) {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			h := f[len(f)-1]
			if _, e := strconv.ParseUint(h, 10, 64); e != nil {
				continue
			}
			if _, e = r.Run("nft", "delete", "rule", "inet", "purewrt", chain, "handle", h); e != nil {
				errs = append(errs, e)
			}
		}
	}
	// Absent objects are expected after an apply/reload or partial setup.
	_, _ = r.Run("nft", "delete", "set", "inet", "purewrt", clientTestName)
	_, _ = r.Run("nft", "delete", "table", "inet", clientTestName)
	_, _ = r.Run("ip", "-4", "rule", "del", "pref", "101", "fwmark", clientTestMark+"/"+clientTestMark, "lookup", clientTestTable)
	_, _ = r.Run("ip", "-4", "rule", "del", "pref", "101", "fwmark", clientTestFakeMark+"/"+clientTestFakeMark, "lookup", clientTestTable)
	_, _ = r.Run("ip", "-4", "route", "flush", "table", clientTestTable)
	if _, e := r.Run("nft", "list", "table", "inet", clientTestName); e == nil {
		errs = append(errs, fmt.Errorf("temporary client table still exists"))
	}
	if _, e := r.Run("nft", "list", "set", "inet", "purewrt", clientTestName); e == nil {
		errs = append(errs, fmt.Errorf("temporary client bypass still exists; it expires automatically"))
	}
	if out, e := r.Run("ip", "-4", "rule", "show"); e != nil {
		errs = append(errs, e)
	} else if strings.Contains(out, "lookup "+clientTestTable) {
		errs = append(errs, fmt.Errorf("temporary client route rule still exists"))
	}
	return errors.Join(errs...)
}

func (m Manager) ZapretClientRun(o ZapretClientOptions) (retErr error) {
	lock, e := system.TryAcquire(clientTestPath(".lock"))
	if e != nil {
		return fmt.Errorf("another client test is running: %w", e)
	}
	defer lock.Close()
	s := ZapretClientState{IP: o.IP, Interface: o.Interface, Candidate: o.Candidate, Extra: o.Extra, Manual: o.Manual}
	defer func() {
		s.Running = false
		s.Phase = "stopped"
		s.ProcessGroup = 0
		if retErr != nil {
			s.Error = retErr.Error()
		}
		_ = clientTestSave(s)
	}()
	if e := clientTestValidate(o); e != nil {
		return e
	}
	_ = os.Remove(clientTestPath(".stop"))
	_ = os.Remove(clientTestPath(".switch"))
	s.Running = true
	s.Phase = "preparing"
	s.Expires = time.Now().Add(clientTestSeconds * time.Second).Unix()
	if e = clientTestSave(s); e != nil {
		return e
	}
	c, e := m.Load()
	if e != nil {
		return e
	}
	candidates, e := clientTestCandidates(o, m.ZapretCandidates())
	if e != nil {
		return e
	}
	r := system.Runner{Timeout: 5 * time.Second}
	// Require a directly attached known client, never a router address or remote host.
	neigh, e := r.Run("ip", "-4", "neigh", "show", o.IP)
	if e != nil || !strings.Contains(strings.ToLower(neigh), "lladdr "+strings.ToLower(o.MAC)) {
		return fmt.Errorf("client is not in the router's neighbor table; wake it and retry")
	}
	addr, e := r.Run("ip", "-4", "addr", "show")
	if e != nil {
		return e
	}
	if strings.Contains(addr, "inet "+o.IP+"/") {
		return fmt.Errorf("cannot test the router itself")
	}
	if strings.Contains(neigh, "dev "+o.Interface+" ") {
		return fmt.Errorf("client must be on a LAN, not the selected WAN")
	}
	mask, e := strconv.ParseUint(c.Settings.FwMarkMask, 0, 32)
	if e != nil || mask&0x18000000 != 0 {
		return fmt.Errorf("PureWRT routing mask conflicts with test marks")
	}
	// The client tester reserves a dedicated table and mark instead of depending on mwan3.
	rules, e := r.Run("ip", "-4", "rule", "show")
	if e != nil {
		return e
	}
	if e = clientTestValidateMarks(c, rules); e != nil {
		return e
	}
	if strings.Contains(rules, "101:") || strings.Contains(rules, "lookup "+clientTestTable) {
		return fmt.Errorf("test routing priority/table is already in use")
	}
	routes, e := r.Run("ip", "-4", "route", "show", "table", clientTestTable)
	if e == nil && strings.TrimSpace(routes) != "" {
		return fmt.Errorf("test route table is already in use")
	}
	routes, e = r.Run("ip", "-4", "route", "show", "default")
	if e != nil {
		return e
	}
	routeArgs, e := clientTestDefaultRoute(routes, o.Interface)
	if e != nil {
		return e
	}
	bin := m.zapretNFQWSBin()
	if bin == "" {
		return fmt.Errorf("nfqws2 not installed")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, clientTestSeconds*time.Second)
	defer timeout()
	args, e := m.clientTestArgs(candidates, clientTestQueue)
	if e != nil {
		return e
	}
	process, e := startClientNFQ(ctx, bin, args, clientTestQueue, clientTestSeconds)
	if e != nil {
		return e
	}
	defer func() { process.stop() }()
	s.ProcessGroup = process.cmd.Process.Pid
	queue := clientTestQueue
	defer func() { retErr = errors.Join(retErr, clientTestCleanup(r)) }()
	if _, e = r.Run("ip", routeArgs...); e != nil {
		return e
	}
	if _, e = r.Run("ip", "-4", "rule", "add", "pref", "101", "fwmark", clientTestMark+"/"+clientTestMark, "lookup", clientTestTable); e != nil {
		return e
	}
	// Generated packets need the same WAN route without sharing the client's bit.
	if _, e = r.Run("ip", "-4", "rule", "add", "pref", "101", "fwmark", clientTestFakeMark+"/"+clientTestFakeMark, "lookup", clientTestTable); e != nil {
		return e
	}
	if _, e = os.Stat(clientTestPath(".stop")); e == nil {
		return nil
	}
	offloadScript, offload, e := clientOffloadPrepare(r, o.IP)
	if e != nil {
		return e
	}
	script := clientTestNFT(o, fmt.Sprintf("0x%x", mask))
	script += offloadScript
	// Production Zapret must not also process this client's candidate traffic.
	if _, e = r.Run("nft", "list", "chain", "inet", "purewrt", "postrouting"); e == nil {
		script += "insert rule inet purewrt postrouting meta mark & 0x10000000 != 0 return comment \"purewrt_client_test\"\n"
		script += fmt.Sprintf("insert rule inet purewrt postrouting ct original ip saddr @%s return comment \"%s\"\n", clientTestName, clientTestName)
	}
	path := filepath.Join(os.TempDir(), clientTestName+".nft")
	if e = system.AtomicWrite(path, []byte(script), 0600); e != nil {
		return e
	}
	defer os.Remove(path)
	if out, e := r.Run("nft", "-f", path); e != nil {
		return fmt.Errorf("install client rules: %s: %w", out, e)
	}
	s.Running = true
	s.Phase = "testing"
	s.Expires = time.Now().Add(clientTestSeconds * time.Second).Unix()
	if e = clientTestSave(s); e != nil {
		return e
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case e = <-process.done:
			return fmt.Errorf("nfqws exited during test: %v", e)
		case <-ticker.C:
			if _, e = os.Stat(clientTestPath(".stop")); e == nil {
				return nil
			}
			if req, err := readClientSwitch(); err == nil {
				if req.Expires != s.Expires {
					continue
				}
				nextQueue := "9910"
				if queue == nextQueue {
					nextQueue = clientTestQueue
				}
				next, switchErr := m.switchClientNFQ(ctx, r, bin, nextQueue, req, s.Expires)
				if switchErr == nil {
					old := process
					process = next
					queue = nextQueue
					s.ProcessGroup = process.cmd.Process.Pid
					s.Candidate, s.Extra, s.Manual, s.Error = req.Candidate, req.Extra, req.Manual, ""
					old.stop()
				} else {
					s.Error = "Strategy switch failed; previous strategy retained: " + switchErr.Error()
				}
				if e = clientTestSave(s); e != nil {
					return e
				}
				result := clientSwitchResult{ID: req.ID}
				if switchErr != nil {
					result.Error = switchErr.Error()
				}
				data, _ := json.Marshal(result)
				_ = system.AtomicWrite(clientTestPath(".switch-result"), data, 0600)
			}
			if offload != nil {
				if _, e = r.Run("nft", "list", "set", "inet", "fw4", clientOffloadName); e != nil {
					return fmt.Errorf("firewall changed; client test stopped")
				}
			}
			if _, e = r.Run("nft", "list", "set", "inet", "purewrt", clientTestName); e != nil {
				return fmt.Errorf("routing configuration changed; test stopped")
			}
		}
	}
}

// Inspect active policy masks, including mwan3 when present, without requiring
// mwan3 installation or enabling proxy-WAN selection just to run a client test.
func clientTestValidateMarks(c config.Config, rules string) error {
	const reserved = uint64(0x18000000)
	for _, p := range c.EnabledZapretProfiles() {
		mark, ok := parseHexMark(p.FwMark)
		if !ok || mark == 0 {
			return fmt.Errorf("zapret profile %q has invalid fwmark %q", p.Name, p.FwMark)
		}
		if mark&reserved != 0 {
			return fmt.Errorf("zapret profile %q mark %s overlaps reserved client-test bits 0x18000000", p.Name, p.FwMark)
		}
	}
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "fwmark" {
				continue
			}
			parts := strings.Split(fields[i+1], "/")
			mask := uint64(0xffffffff)
			if len(parts) > 1 {
				var err error
				mask, err = strconv.ParseUint(parts[1], 0, 32)
				if err != nil {
					return fmt.Errorf("invalid active routing mask in %q", line)
				}
			}
			if mask&reserved != 0 {
				return fmt.Errorf("active routing rule %q overlaps reserved client-test bits 0x18000000", strings.TrimSpace(line))
			}
		}
	}
	return nil
}

func (m Manager) clientTestArgs(candidates []config.ZapretCandidate, queue string) ([]string, error) {
	args := []string{"--bind-fix4", "--bind-fix6", "--qnum=" + queue, "--fwmark=" + clientTestFakeMark, "--user=daemon", "--debug=0"}
	args = append(args, m.zapretLuaInitArgs()...)
	blobs := map[string]string{}
	for _, cand := range candidates {
		for _, b := range cand.Blobs {
			p, e := m.zapretBlobValue(b)
			if e != nil {
				return nil, e
			}
			if old, ok := blobs[b.Name]; ok && old != p {
				return nil, fmt.Errorf("conflicting blob %s", b.Name)
			}
			blobs[b.Name] = p
		}
	}
	for name, p := range blobs {
		args = append(args, "--blob="+name+":"+p)
	}
	for i, cand := range candidates {
		if i > 0 {
			args = append(args, "--new")
		}
		args = append(args, strings.Fields(cand.Params)...)
	}
	return args, nil
}

// Manual input uses the library option allowlist, without writing a library file.
func clientManualCandidate(params string) (config.ZapretCandidate, error) {
	c := config.ZapretCandidate{Name: "user_manual_test", Params: strings.Join(strings.Fields(params), " ")}
	if len(params) > 16384 {
		return c, fmt.Errorf("manual parameters exceed 16 KiB")
	}
	for _, protocol := range []string{"tcp", "udp"} {
		var ports []string
		for _, arg := range strings.Fields(c.Params) {
			if value, ok := strings.CutPrefix(arg, "--filter-"+protocol+"="); ok {
				ports = append(ports, value)
			}
		}
		if len(ports) > 0 {
			c.Protocols = append(c.Protocols, protocol)
			if protocol == "tcp" {
				c.TCPPorts = strings.Join(ports, ",")
			} else {
				c.UDPPorts = strings.Join(ports, ",")
			}
		}
	}
	return c, validateLibraryCandidate(c)
}
