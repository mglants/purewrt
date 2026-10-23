package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

// OONIRun is the shared cron/LuCI entry point. Empty WAN selection keeps the
// normal routing/resolver behavior and does not require mwan3 or namespaces.
func (m Manager) OONIRun(ctx context.Context, args []string) error {
	noCollector, input, err := ooniRunArgs(args)
	if err != nil {
		return err
	}
	c, err := m.Load()
	if err != nil {
		return err
	}
	c = ResolveOONIUser(config.EnsureDefaults(c))
	if !c.OONI.Enabled || c.OONI.UID <= 0 {
		return fmt.Errorf("ooni: enable OONI and configure a dedicated non-root user first")
	}
	lock, err := system.TryAcquire(filepath.Join(c.Settings.RuntimeDir, "ooni-run.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if ooniRunning() {
		return fmt.Errorf("ooni: another probe is running")
	}
	o := c.OONISettings()
	if noCollector {
		c.OONI.Upload = false
	}
	var wans []config.ProxyWAN
	if len(o.WANs) > 0 {
		// Reuse discovery without coupling OONI to proxy-WAN enablement.
		discover := c
		discover.Mwan3.ProxyWANEnabled = true
		discover.Mwan3.ProxyWANs = o.WANs
		discover, err = ResolveProxyWANs(discover)
		if err != nil {
			return err
		}
		wans = discover.Mwan3.ResolvedProxyWANs
	} else {
		wans = []config.ProxyWAN{{}}
	}
	var failures []error
	for _, wan := range wans {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		run := c
		run.OONI.Home = o.Home
		if wan.Name != "" {
			run.OONI.Home = filepath.Join(o.Home, "wan-"+wan.Name)
		}
		if noCollector {
			run.OONI.Home += "-local"
		}
		fmt.Printf("OONI: starting WAN=%s device=%s home=%s\n", ooniWANLabel(wan), wan.Device, run.OONI.Home)
		err := m.runOONIWAN(ctx, run, wan, noCollector, input)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ooniWANLabel(wan), err))
			fmt.Printf("OONI: WAN=%s failed: %v\n", ooniWANLabel(wan), err)
		} else {
			fmt.Printf("OONI: WAN=%s completed\n", ooniWANLabel(wan))
		}
	}
	return errors.Join(failures...)
}

func ooniWANLabel(w config.ProxyWAN) string {
	if w.Name == "" {
		return "router-default"
	}
	return w.Name
}

func ooniRunArgs(args []string) (bool, string, error) {
	noCollector, input := false, ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-collector":
			noCollector = true
		case "--input":
			i++
			if i == len(args) {
				return false, "", fmt.Errorf("--input requires a URL")
			}
			input = args[i]
		default:
			return false, "", fmt.Errorf("unknown ooni-run argument %q", args[i])
		}
	}
	return noCollector, input, nil
}

func (m Manager) runOONIWAN(ctx context.Context, c config.Config, wan config.ProxyWAN, noCollector bool, input string) (err error) {
	if err = prepareOONIHome(c, m.OONIInstalled()); err != nil {
		return err
	}
	o := c.OONISettings()
	r := system.Runner{}
	resolver := ""
	if wan.Name != "" {
		status, e := r.Run("ubus", "call", "network.interface."+wan.Name, "status")
		if e != nil {
			return e
		}
		dns, e := ooniWANDNS(status, wan.Device)
		if e != nil {
			return e
		}
		// Root-owned private resolver input: never bind a file writable by the probe.
		f, e := os.CreateTemp("", "purewrt-ooni-resolv-")
		if e != nil {
			return e
		}
		resolver = f.Name()
		defer os.Remove(resolver)
		_, e = f.WriteString(dns)
		if ce := f.Close(); e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
		if e = os.Chmod(resolver, 0644); e != nil {
			return e
		}
		cleanup, e := installOONIRoutes(r, c.OONI.UID, wan.Table)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, cleanup()) }()
		removeNFT, e := installOONIMark(r, c.OONI.UID, wan)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, removeNFT()) }()

	}
	argv := []string{"--log-handler=cli", "--proxy", o.Proxy, "run"}
	if noCollector || !o.Upload {
		argv = append(argv, "--no-collector")
	}
	if input != "" {
		argv = append(argv, "websites", "--input", input)
	} else {
		argv = append(argv, "unattended")
	}
	// Exec helper enters a PRIVATE mount namespace before dropping privileges.
	// The namespace dies with the probe; no host resolver is ever rewritten.
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := append([]string{"ooni-exec", resolver, o.User}, argv...)
	runCtx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	cmd := exec.CommandContext(runCtx, exe, childArgs...)
	cmd.Env = append(os.Environ(), "OONI_HOME="+o.Home)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	err = cmd.Run()
	if runCtx.Err() != nil {
		return runCtx.Err()
	}
	return err
}

func ooniWANDNS(status, device string) (string, error) {
	var s struct {
		Up       bool     `json:"up"`
		Device   string   `json:"l3_device"`
		DNS      []string `json:"dns-server"`
		Inactive struct {
			DNS []string `json:"dns-server"`
		} `json:"inactive"`
	}
	if err := json.Unmarshal([]byte(status), &s); err != nil {
		return "", err
	}
	if !s.Up || s.Device != device {
		return "", fmt.Errorf("WAN is down or its device changed")
	}
	dns := s.DNS
	if len(dns) == 0 {
		dns = s.Inactive.DNS
	} // peerdns=0 retains advertised servers here.
	var lines []string
	for _, addr := range uniqueStrings(dns) {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		lines = append(lines, "nameserver "+ip.String())
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("WAN has no advertised IPv4 DNS servers; refusing shared router DNS")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// Reserve priorities immediately before PureWRT's LAN-prefix rule. Loopback
// remains reachable via priority 0, including the backend SOCKS listener.
// Install the rejection rules first, remove them last. A missing WAN route
// must fail rather than fall through to main or another mwan3 policy.
func installOONIRoutes(r commandRunner, uid int, table string) (func() error, error) {
	if uid <= 0 || table == "" {
		return nil, fmt.Errorf("invalid OONI route identity")
	}
	for _, family := range []string{"-4", "-6"} {
		out, err := r.Run("ip", family, "rule", "show")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && (f[0] == "97:" || f[0] == "98:") {
				return nil, fmt.Errorf("OONI route priority 97/98 already occupied (%s); inspect stale rules before retrying", family)
			}
		}
	}
	who := strconv.Itoa(uid) + "-" + strconv.Itoa(uid)
	rules := [][]string{
		{"-4", "rule", "add", "pref", "98", "uidrange", who, "unreachable"},
		{"-6", "rule", "add", "pref", "98", "uidrange", who, "unreachable"},
		{"-4", "rule", "add", "pref", "97", "uidrange", who, "lookup", table},
	}
	var installed [][]string
	cleanup := func() error {
		var errs []error
		for i := len(installed) - 1; i >= 0; i-- {
			a := append([]string(nil), installed[i]...)
			a[2] = "del"
			if _, e := r.Run("ip", a...); e != nil {
				errs = append(errs, fmt.Errorf("remove OONI rule %v: %w", a, e))
			}
		}
		return errors.Join(errs...)
	}
	for _, a := range rules {
		if _, err := r.Run("ip", a...); err != nil {
			return nil, errors.Join(err, cleanup())
		}
		installed = append(installed, a)
	}
	return cleanup, nil
}

// OONIExec is an internal re-exec entry point. The mount namespace is created
// here (not assumed), so even a manual invocation cannot change host mounts.
// start-stop-daemon resolves both UID and primary GID without cgo or su.
func OONIExec(args []string) error {
	if len(args) < 3 || os.Geteuid() != 0 {
		return fmt.Errorf("invalid OONI exec invocation")
	}
	resolver, user := args[0], args[1]
	if lookupUID(user, "/etc/passwd") <= 0 {
		return fmt.Errorf("OONI requires a non-root user")
	}
	runtime.LockOSThread()
	// Do not unlock: this thread must never return to Go's thread pool after
	// unshare. The command entry point exits on any error.
	if resolver != "" {
		if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
			return fmt.Errorf("OONI requires mount namespaces: %w", err)
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			return err
		}
		target, err := filepath.EvalSymlinks("/etc/resolv.conf")
		if err != nil {
			return err
		}
		if err = syscall.Mount(resolver, target, "", syscall.MS_BIND, ""); err != nil {
			return err
		}
	}
	bin, err := exec.LookPath("start-stop-daemon")
	if err != nil {
		return err
	}
	argv := append([]string{bin, "-S", "-c", user, "-x", "/usr/bin/ooniprobe", "--"}, args[2:]...)
	return syscall.Exec(bin, argv, os.Environ())
}

// mwan3 can restore conntrack marks in OUTPUT and reroute without retaining
// the socket UID in the lookup. Set the WAN mark after mwan3's mangle hook.
// A later output guard rejects any wrong-device egress, including IPv6.
func installOONIMark(r commandRunner, uid int, wan config.ProxyWAN) (func() error, error) {
	if _, err := r.Run("nft", "list", "table", "inet", "purewrt_ooni"); err == nil {
		return nil, fmt.Errorf("OONI nft table already exists; inspect stale state before retrying")
	}
	script := fmt.Sprintf(
		"add table inet purewrt_ooni\n"+
			"add chain inet purewrt_ooni egress { type route hook output priority -149; policy accept; }\n"+
			"add rule inet purewrt_ooni egress meta skuid %d meta nfproto ipv4 meta mark set (meta mark & 0x%x) | 0x%x\n"+
			"add chain inet purewrt_ooni guard { type filter hook output priority 1; policy accept; }\n"+
			"add rule inet purewrt_ooni guard meta skuid %d oifname \"lo\" accept\n"+
			"add rule inet purewrt_ooni guard meta skuid %d meta nfproto ipv6 reject\n"+
			"add rule inet purewrt_ooni guard meta skuid %d oifname != %q reject\n",
		uid, ^wan.Mask, wan.Mark, uid, uid, uid, wan.Device)
	f, err := os.CreateTemp("", "purewrt-ooni-nft-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(script)
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, err
	}
	if out, e := r.Run("nft", "-f", f.Name()); e != nil {
		return nil, fmt.Errorf("install OONI WAN mark: %w: %s", e, out)
	}
	return func() error { _, e := r.Run("nft", "delete", "table", "inet", "purewrt_ooni"); return e }, nil
}
