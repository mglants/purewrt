package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/generator"
	"github.com/purewrt/purewrt/internal/geodb"
	"github.com/purewrt/purewrt/internal/ipdb"
	"github.com/purewrt/purewrt/internal/logging"
	"github.com/purewrt/purewrt/internal/manager"
	"github.com/purewrt/purewrt/internal/provider"
	"github.com/purewrt/purewrt/internal/system"
)

// stripJSONFlag pulls --json out of the argument slice (anywhere it appears)
// and returns the remaining args plus a bool indicating it was set. Lets the
// CLI dispatcher offer dual human/JSON output on the same subcommand without
// stricter flag-package machinery.
func stripJSONFlag(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	jsonFlag := false
	for _, a := range args {
		if a == "--json" {
			jsonFlag = true
			continue
		}
		out = append(out, a)
	}
	return out, jsonFlag
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "json encode failed:", err)
		os.Exit(1)
	}
}

func containsColon(s string) bool { return strings.Contains(s, ":") }

// parseTargets turns positional canary args into CanaryProbes, defaulting
// to port :443 + TLS when only a hostname was given. Empty slice returns
// nil so callers can substitute their default list.
func parseTargets(args []string) []checker.CanaryProbe {
	if len(args) == 0 {
		return nil
	}
	out := make([]checker.CanaryProbe, 0, len(args))
	for _, t := range args {
		target := t
		if !containsColon(t) {
			target = t + ":443"
		}
		out = append(out, checker.CanaryProbe{Target: target, UseTLS: true})
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// stripFlag removes occurrences of `flag` (e.g. "--no-restart") from args
// and reports whether it was present. Used by subcommands that accept a
// single boolean flag alongside positional args without dragging in
// flag.FlagSet machinery.
func stripFlag(args []string, flag string) ([]string, bool) {
	out := make([]string, 0, len(args))
	present := false
	for _, a := range args {
		if a == flag {
			present = true
			continue
		}
		out = append(out, a)
	}
	return out, present
}

func contextWithTimeout(seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
}

// runFirstAvailable executes the first existing script in paths with the
// `restart` action. Used by `purewrt zapret-restart` to drive whichever
// init script the host actually ships. Output goes straight to stdout/stderr.
func runFirstAvailable(paths ...string) {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p, "restart")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintln(os.Stderr, p, "restart failed:", err)
				os.Exit(1)
			}
			return
		}
	}
	fmt.Fprintln(os.Stderr, "no zapret init script found in:", strings.Join(paths, " "))
	os.Exit(1)
}

// ResolveZapretProfileInterfaces is exposed by the manager package; re-export
// as a tiny local helper so the doctor --json path doesn't reach into
// internals from the CLI.
var ResolveZapretProfileInterfaces = manager.ResolveZapretProfileInterfaces

const (
	operationLockPath    = "/var/run/purewrt.lock"
	operationDirtyPath   = "/var/run/purewrt.dirty"
	operationLockMaxWait = 5 * time.Minute
	// operationCoalesceCap bounds the holder's catch-up loop so a pathological
	// stream of new requests can't keep us looping forever. In practice 2-3
	// iterations is the worst we ever see; 10 is generous.
	operationCoalesceCap = 10
)

func main() {
	m := manager.Manager{}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	log := commandLogger(m)
	defer log.DebugTimer("command: %s", cmd)()
	log.Debug("command: %s start", cmd)
	switch cmd {
	case "analyze":
		need(3)
		a, err := m.Analyze(os.Args[2])
		fatal(err)
		b, _ := json.MarshalIndent(a, "", "  ")
		fmt.Println(string(b))
	case "import":
		need(3)
		// --proxy-only imports proxy providers without rule providers (the
		// wizard's Default-lists flow uses it to give proxy sections nodes).
		mode := "auto"
		for _, a := range os.Args[3:] {
			if a == "--proxy-only" {
				mode = "proxy_only"
			}
		}
		withOperationLockCoalesce(func() {
			plan, err := m.Import(os.Args[2], "", mode, "minimal")
			fatal(err)
			fmt.Print(plan.Text())
			res, err := m.UpdateDetailed()
			fatal(err)
			if res.Changed {
				fatal(m.Apply())
				fmt.Println("subscription imported, providers updated and PureWRT applied")
			} else {
				fatal(m.Apply())
				fmt.Println("subscription imported and PureWRT applied")
			}
		})
	case "preview", "diff":
		need(3)
		out, err := m.Preview(os.Args[2])
		fatal(err)
		fmt.Println(out)
	case "classify":
		need(3)
		url, behavior, format := "", "", ""
		if len(os.Args) > 3 {
			url = os.Args[3]
		}
		if len(os.Args) > 4 {
			behavior = os.Args[4]
		}
		if len(os.Args) > 5 {
			format = os.Args[5]
		}
		out, err := m.Classify(os.Args[2], url, behavior, format)
		fatal(err)
		fmt.Println(out)
	case "rule-provider-status":
		out, err := m.RuleProviderStatusJSON()
		fatal(err)
		fmt.Println(out)
	case "override":
		need(4)
		fatal(m.OverrideRuleProvider(os.Args[2], os.Args[3:]))
		fmt.Println("override saved")
	case "add-native-list":
		// add-native-list <url> <section> [--no-apply] [--priority=N]: register
		// a pre-built nftset-builder list as a native_import provider, creating
		// the section if missing. --no-apply only persists (the wizard batches
		// many, then applies once); otherwise fetch + apply for standalone CLI
		// use. --priority=N sets the rule provider + new-section precedence.
		need(4)
		noApply := false
		priority := 0
		for _, a := range os.Args[4:] {
			switch {
			case a == "--no-apply":
				noApply = true
			case strings.HasPrefix(a, "--priority="):
				priority, _ = strconv.Atoi(strings.TrimPrefix(a, "--priority="))
			}
		}
		name, err := m.AddNativeList(os.Args[2], os.Args[3], priority)
		fatal(err)
		if noApply {
			printJSON(map[string]string{"name": name})
		} else {
			if _, err := m.UpdateRuleProvider(name); err != nil {
				fatal(err)
			}
			fatal(m.Apply())
			fmt.Println("native list added and applied:", name)
		}
	case "wizard-reset":
		// Flush config to defaults, preserving VPN/Zapret + credentials +
		// mihomo binary selection. Used by the wizard's "start over" apply.
		fatal(m.WizardReset())
		fmt.Println("config reset (VPN/Zapret/credentials preserved)")
	case "default-lists-catalog":
		// Fetch <default_lists_base_url>/catalog.json via the bootstrap client.
		out, err := m.DefaultListsCatalog()
		fatal(err)
		os.Stdout.Write(out)
	case "update":
		withOperationLockCoalesce(func() {
			force := len(os.Args) > 2 && os.Args[2] == "--force"
			res, err := m.UpdateDetailedWithOptions(force)
			fatal(err)
			if res.Changed {
				fmt.Println("providers and rule-providers updated")
			} else if force {
				fmt.Println("providers and rule-providers refreshed; no content changes")
			} else {
				fmt.Println("no provider changes")
			}
		})
	case "update-rule-provider":
		need(3)
		// Hot-reload bypasses the full purewrt apply by asking mihomo to
		// re-read the provider in place — useful when the on-disk file
		// hasn't changed (no checksum diff) but mihomo's internal rule
		// engine should be poked anyway, or when the user just doesn't
		// want the cost of a full regen.
		args, hotReload := stripFlag(os.Args[2:], "--no-restart")
		if len(args) < 1 {
			need(3) // re-fire the usage check
		}
		name := args[0]
		withOperationLock(func() {
			res, err := m.UpdateRuleProvider(name)
			fatal(err)
			if hotReload {
				if err := m.UpdateRuleProviderHotReload(name); err != nil {
					fmt.Fprintln(os.Stderr, "hot-reload failed, falling back to apply:", err)
					fatal(m.Apply())
				}
				fmt.Println("rule provider updated and hot-reloaded")
				return
			}
			if res.Changed {
				fatal(m.Apply())
				fmt.Println("rule provider updated and applied")
			} else {
				fmt.Println("rule provider unchanged")
			}
		})
	case "update-proxy-provider":
		need(3)
		withOperationLock(func() {
			res, err := m.UpdateProxyProvider(os.Args[2])
			fatal(err)
			if res.Changed {
				fatal(m.Apply())
				fmt.Println("proxy provider updated and applied")
			} else {
				fmt.Println("proxy provider unchanged")
			}
		})
	case "update-if-needed":
		withOperationLockCoalesce(func() {
			force := len(os.Args) > 2 && os.Args[2] == "--force"
			res, err := m.UpdateDetailedWithOptions(force)
			fatal(err)
			if !res.Changed && !force {
				fmt.Println("no provider changes")
				return
			}
			fatal(m.ApplyWithOptions(force))
			fmt.Println("providers changed; PureWRT applied")
		})
	case "mihomo-check-update":
		// Optional positional arg: channel (alpha|stable). Defaults to
		// the configured channel (alpha for legacy installs).
		channel := ""
		if len(os.Args) > 2 {
			channel = os.Args[2]
		}
		info, err := m.MihomoCheckUpdateChannel(channel)
		fatal(err)
		printJSON(info)
	case "mihomo-download", "mihomo-update":
		info, err := m.MihomoPackageUpdate()
		fatal(err)
		fmt.Printf("mihomo-alpha package update available: %s (%s). Rebuild/install the bundled mihomo-alpha package; binary overwrite is disabled.\n", info.Version, info.AssetName)
	case "mihomo-install-release":
		// Real binary install from MetaCubeX GitHub release. Channel arg
		// required (alpha|stable). Downloads → verifies SHA256 →
		// installs to <workdir>/mihomo-bin/ → flips UCI MihomoBin →
		// restarts service.
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: purewrt mihomo-install-release <alpha|stable>")
			os.Exit(2)
		}
		res, err := m.MihomoInstallRelease(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "mihomo-install-release:", err)
			os.Exit(1)
		}
		printJSON(res)
	case "mihomo-revert-package":
		fatal(m.MihomoRevertToPackage())
		fmt.Println("reverted to package-installed mihomo; restarted")
	case "mihomo-auto-update":
		// Cron entry — quiet on the happy path, loud on action. The
		// init script's cron block pipes our stdout through logger so
		// every tick lands in syslog under purewrt-cron, even the
		// up-to-date ones — useful for confirming the schedule fires.
		res, err := m.MihomoAutoUpdate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "mihomo-auto-update:", err)
		}
		printJSON(res)
	case "mihomo-status":
		printJSON(m.MihomoStatus())
	case "mihomo-mixin-get":
		info, err := m.MihomoMixinRead()
		fatal(err)
		printJSON(info)
	case "mihomo-mixin-set":
		// Mixin body comes from stdin; the rpcd dispatcher pipes the
		// JSON body's `body` field through. Empty stdin → delete the
		// mixin file (deliberate "clear" gesture).
		body, _ := io.ReadAll(os.Stdin)
		fatal(m.MihomoMixinWrite(string(body)))
		fmt.Println("ok")
	case "mihomo-mixin-preview":
		body, _ := io.ReadAll(os.Stdin)
		out, err := m.MihomoMixinPreview(string(body))
		fatal(err)
		fmt.Print(out)
	case "updates-available":
		force := len(os.Args) > 2 && os.Args[2] == "--force"
		updates, err := m.AptUpdatesAvailable(force)
		fatal(err)
		printJSON(updates)
	case "generate":
		force := len(os.Args) > 2 && os.Args[2] == "--force"
		fatal(m.GenerateWithOptions(force))
		fmt.Println("generated mihomo, dnsmasq and nftables config")
	case "generate-cache-status":
		out, err := m.GenerateCacheStatus()
		fatal(err)
		fmt.Print(out)
	case "cache-clean":
		fatal(m.CacheClean())
		fmt.Println("PureWRT rule artifact cache removed")
	case "prune-orphans":
		// Remove provider files (rulesets/providers/cache) with no matching
		// configured provider. --dry-run only lists them. Apply does this
		// automatically; this is for manual/auditable invocation.
		dryRun := len(os.Args) > 2 && os.Args[2] == "--dry-run"
		removed, err := m.PruneOrphans(dryRun)
		fatal(err)
		for _, p := range removed {
			fmt.Println(p)
		}
		if dryRun {
			fmt.Printf("%d orphan provider file(s) would be removed\n", len(removed))
		} else {
			fmt.Printf("%d orphan provider file(s) removed\n", len(removed))
		}
	case "apply", "reload":
		withOperationLockCoalesce(func() {
			force := len(os.Args) > 2 && os.Args[2] == "--force"
			fatal(m.ApplyWithOptions(force))
			fmt.Println("applied PureWRT safely")
		})
	case "status":
		fmt.Print(m.Status())
	case "statistics", "stats":
		out, err := m.StatisticsJSON()
		fatal(err)
		fmt.Println(out)
	case "validate":
		fatal(m.Validate())
		fmt.Println("validation OK")
	case "proxy-groups":
		// JSON array of mihomo proxy groups with member health. The rpcd
		// dispatcher wraps it in {items:[...]} (ubus rejects bare arrays).
		groups, err := m.ProxyGroups()
		fatal(err)
		printJSON(groups)
	case "proxy-select":
		need(4)
		drain := !(len(os.Args) > 4 && os.Args[4] == "--no-drain")
		res, err := m.ProxySelect(os.Args[2], os.Args[3], drain)
		fatal(err)
		printJSON(res)
	case "proxy-delay-test":
		need(3)
		delays, err := m.ProxyDelayTest(os.Args[2])
		fatal(err)
		printJSON(delays)
	case "export":
		// Portable UCI-text dump of the full config. Secrets (controller
		// secret, subscription tokens in URLs, HWIDs) are redacted unless
		// --include-secrets is passed — exports get pasted into issues.
		includeSecrets := len(os.Args) > 2 && os.Args[2] == "--include-secrets"
		out, err := m.ExportConfig(includeSecrets)
		fatal(err)
		fmt.Print(out)
	case "import-config":
		// Validates before replacing /etc/config/purewrt; never applies.
		// `-` reads stdin so the rpcd dispatcher can pipe the body through.
		need(3)
		var data []byte
		var err error
		if os.Args[2] == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(os.Args[2])
		}
		fatal(err)
		res, err := m.ImportConfig(data)
		fatal(err)
		printJSON(res)
	case "doctor":
		// `--resolvers` and `--warnings` flag forms previously duplicated
		// `resolvers-probe` and `doctor-warnings` standalone subcommands.
		// The rpcd shim only invokes the standalone forms, and the CLI's
		// `purewrt --help` output already lists the standalone form, so
		// the flag aliases were strictly redundant. Removed to keep one
		// canonical name per operation.
		args, asJSON := stripJSONFlag(os.Args[2:])
		if len(args) > 0 && args[0] == "--canaries" {
			rest := args[1:]
			// Parse out --report, --whitelist=host:port, --blacklist=host:port.
			// Positional args without a prefix go into the blacklist
			// (back-compat with `purewrt doctor --canaries foo.com:443`).
			report := false
			var whitelist, blacklist, positional []string
			for _, a := range rest {
				switch {
				case a == "--report":
					report = true
				case strings.HasPrefix(a, "--whitelist="):
					whitelist = append(whitelist, strings.TrimPrefix(a, "--whitelist="))
				case strings.HasPrefix(a, "--blacklist="):
					blacklist = append(blacklist, strings.TrimPrefix(a, "--blacklist="))
				default:
					positional = append(positional, a)
				}
			}
			if len(blacklist) == 0 {
				blacklist = positional
			}
			if report {
				// BlockingReport: whitelist (control) + blacklist (suspected)
				// + overall verdict. Empty lists fall back to Go defaults.
				ctx, cancel := contextWithTimeout(180)
				defer cancel()
				rep := checker.BlockingReportRun(ctx, parseTargets(whitelist), parseTargets(blacklist))
				if asJSON {
					printJSON(rep)
					return
				}
				fmt.Print(checker.FormatBlockingReport(rep))
				return
			}
			// Legacy flat path: positional/blacklist args are the canary
			// list; whitelist is ignored (only the BlockingReport path
			// uses it). Preserved so existing rpcd callers and scripts
			// don't break.
			if asJSON {
				ctx, cancel := contextWithTimeout(90)
				defer cancel()
				probes := parseTargets(blacklist)
				if len(probes) == 0 {
					probes = checker.DefaultBlockingCanaries()
				}
				printJSON(checker.BlockingHeuristics(ctx, probes))
				return
			}
			fmt.Print(m.BlockingHeuristics(blacklist))
			return
		}
		if asJSON {
			// Whole doctor: emit a JSON object with each component.
			c, _ := m.Load()
			c = ResolveZapretProfileInterfaces(c)
			printJSON(map[string]any{
				"warnings": m.DoctorWarnings(),
				"ipv6":     checker.InspectIPv6(c),
			})
			return
		}
		fmt.Print(m.Doctor())
	case "resolvers-probe":
		args, asJSON := stripJSONFlag(os.Args[2:])
		canary := ""
		if len(args) > 0 {
			canary = args[0]
		}
		r := m.ResolversProbe(canary)
		if asJSON {
			printJSON(r)
		} else {
			fmt.Print(manager.FormatResolversProbe(r))
		}
		if !r.Anywhere {
			os.Exit(1)
		}
	case "inspect-ipv6":
		printJSON(m.InspectIPv6())
	case "dpi-check":
		// TCP-16-20 matrix probe (ported from hyperion-cs/dpi-checkers).
		// Usage: purewrt dpi-check <host> [--ip=<ipv4>] [--timeout=<sec>] [--json]
		// Long-running (~90-150 s for the full matrix). Default output is an
		// ANSI-coloured table (the JSON form is for rpcd / scripts; pass
		// --json to force it).
		args, asJSON := stripJSONFlag(os.Args[2:])
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: purewrt dpi-check <host> [--ip=<ipv4>] [--timeout=<sec>] [--json]")
			os.Exit(2)
		}
		probe := checker.TCP1620Probe{Host: args[0]}
		for _, a := range args[1:] {
			switch {
			case strings.HasPrefix(a, "--ip="):
				probe.IP = strings.TrimPrefix(a, "--ip=")
			case strings.HasPrefix(a, "--timeout="):
				n, err := strconv.Atoi(strings.TrimPrefix(a, "--timeout="))
				if err == nil && n > 0 {
					probe.Timeout = time.Duration(n) * time.Second
				}
			}
		}
		ctx, cancel := contextWithTimeout(300)
		defer cancel()
		rep, err := checker.RunTCP1620(ctx, probe)
		fatal(err)
		if asJSON {
			printJSON(rep)
		} else {
			fmt.Print(checker.FormatTCP1620(rep))
		}
	case "client-traffic":
		// Diagnose blocked flows for one LAN client. Two modes:
		//   purewrt client-traffic <IP> [--seconds=N] [--json]      → snapshot
		//   purewrt client-traffic <IP> --live [--max-seconds=N]    → NDJSON stream
		// The JSON form is for rpcd / scripts; the snapshot table is human-readable.
		args, asJSON := stripJSONFlag(os.Args[2:])
		args, isLive := stripFlag(args, "--live")
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: purewrt client-traffic <IP> [--seconds=N] [--live --max-seconds=N] [--json]")
			os.Exit(2)
		}
		ip := args[0]
		seconds := 30
		maxSeconds := 300
		for _, a := range args[1:] {
			switch {
			case strings.HasPrefix(a, "--seconds="):
				if n, err := strconv.Atoi(strings.TrimPrefix(a, "--seconds=")); err == nil {
					seconds = n
				}
			case strings.HasPrefix(a, "--max-seconds="):
				if n, err := strconv.Atoi(strings.TrimPrefix(a, "--max-seconds=")); err == nil {
					maxSeconds = n
				}
			}
		}
		if isLive {
			// Live mode: NDJSON one-event-per-line to stdout until ctx cancels.
			if maxSeconds < 10 {
				maxSeconds = 10
			}
			if maxSeconds > 600 {
				maxSeconds = 600
			}
			ctx, cancel := contextWithTimeout(maxSeconds)
			defer cancel()
			// Honour SIGTERM/SIGINT so the rpcd-driven background job can be stopped cleanly.
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			go func() { <-sigCh; cancel() }()
			enc := json.NewEncoder(os.Stdout)
			var encMu sync.Mutex
			emit := func(e manager.Event) {
				encMu.Lock()
				defer encMu.Unlock()
				_ = enc.Encode(e)
			}
			if err := m.ClientTrafficStream(ctx, ip, manager.StreamOpts{}, emit); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "client-traffic:", err)
				os.Exit(1)
			}
			return
		}
		// Snapshot mode.
		rep, err := m.ClientTrafficSnapshot(ip, seconds, manager.StreamOpts{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "client-traffic:", err)
			os.Exit(1)
		}
		if asJSON {
			printJSON(rep)
		} else {
			fmt.Print(formatClientTrafficReport(rep))
		}
	case "zapret-installed":
		// Cheap stat-based check the LuCI side uses to gate Zapret-only
		// UI (logs panel, diagnostics section). Menu entry hiding is
		// driven by /usr/bin/nfqws's depends.fs, not by this method.
		printJSON(map[string]bool{"installed": m.ZapretInstalled()})
	case "ooni-installed":
		// Stat-based gate for the OONI LuCI page (ooniprobe is an optional
		// 25.12-only companion package).
		printJSON(map[string]bool{"installed": m.OONIInstalled()})
	case "ooni-status":
		printJSON(m.OONIStatus())
	case "ooni-prepare":
		// Writes the ooniprobe home + config.json (informed consent + upload
		// flag), chowned to the ooni user. Invoked as root by the cron
		// wrapper before su-ing to the ooni user for the measurement.
		fatal(m.OONIPrepare())
	case "ipdb-status":
		// Cheap stat-only status; loadCount=false because the CLI is also
		// invoked from rpcd-driven LuCI poll where we want sub-100ms
		// response time. Path is derived from the user's configured
		// Workdir so non-default installs land in the right place.
		c, _ := m.Load()
		printJSON(ipdb.CheckStatus(ipdb.GZPath(c.Settings.Workdir), false))
	case "ipdb-asn":
		// Expand one ASN to its full CIDR list. Used by the LuCI manual
		// picker's "Add entire AS<n>" option so the user can route an
		// entire Autonomous System (Telegram, Cloudflare, etc.) through a
		// section in one gesture.
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: purewrt ipdb-asn <asn>")
			os.Exit(2)
		}
		asn64, err := strconv.ParseUint(os.Args[2], 10, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid asn:", err)
			os.Exit(2)
		}
		c, _ := m.Load()
		db, err := ipdb.Load(ipdb.GZPath(c.Settings.Workdir))
		if err != nil {
			fmt.Fprintln(os.Stderr, "ipdb load:", err)
			os.Exit(1)
		}
		printJSON(db.PrefixesForASN(uint32(asn64)))
	case "ipdb-update":
		// Synchronous download. Caller (LuCI) uses the start/poll bg-job
		// pattern via rpcd because the body transfer can take 10–30 s on
		// a slow uplink and would exceed ubus's 30 s call timeout. The
		// CLI itself is single-shot here; rpcd does the backgrounding.
		ctx, cancel := contextWithTimeout(300)
		defer cancel()
		// Manager wrapper applies the shared download tactics (bootstrap
		// DoH, optional update-via-proxy, local-proxy fallback) and always
		// targets the combined v4+v6 dataset.
		res, err := m.IPDBUpdate(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ipdb-update:", err)
			os.Exit(1)
		}
		printJSON(res)
	case "doctor-warnings":
		printJSON(m.DoctorWarnings())
	case "subscription-expiry":
		printJSON(m.SubscriptionExpiry())
	case "mihomo-traffic-sample":
		s, err := m.MihomoTrafficSample()
		if err != nil {
			fmt.Fprintln(os.Stderr, "mihomo traffic:", err)
			os.Exit(1)
		}
		printJSON(s)
	case "zapret-compiled-opt":
		c, err := m.Load()
		fatal(err)
		fmt.Print(string(generator.ZapretUpstreamConfig(c)))
	case "zapret-restart":
		// Try upstream init first, then fall back to the legacy PureWRT one.
		// Errors are non-fatal so the rpcd caller always gets a uniform JSON.
		runFirstAvailable("/etc/init.d/zapret2", "/etc/init.d/purewrt-zapret")
	case "geo-refresh":
		args, asJSON := stripJSONFlag(os.Args[2:])
		_ = args
		res, err := m.GeoRefresh()
		if asJSON {
			printJSON(map[string]any{"ok": err == nil, "result": res, "error": errString(err)})
			return
		}
		for _, t := range res.Targets {
			status := "ok"
			if t.Skipped {
				status = "skip"
			} else if !t.OK {
				status = "fail"
			}
			fmt.Printf("  %-5s  %-7s  %s  %d bytes  %s\n", t.Name, status, t.Path, t.Bytes, t.Reason)
		}
		if res.ReloadOK {
			fmt.Println("mihomo: configs reloaded")
		} else if res.ReloadErr != "" {
			fmt.Println("mihomo reload failed:", res.ReloadErr)
		}
		if err != nil {
			os.Exit(1)
		}
	case "flush-dns-sets":
		// Diagnostics: empty the dynamic dns_* nftables sets. They repopulate
		// from dnsmasq on the next client query. Used by the LuCI diagnostics button.
		_, asJSON := stripJSONFlag(os.Args[2:])
		flushed, err := m.FlushDynamicDNSSets()
		if asJSON {
			printJSON(map[string]any{"ok": err == nil, "flushed": flushed, "count": len(flushed), "error": errString(err)})
			return
		}
		if err != nil {
			fmt.Println("flush-dns-sets failed:", err)
			os.Exit(1)
		}
		fmt.Printf("flushed %d dynamic dns sets\n", len(flushed))
	case "geo-list":
		// Enumerate categories/countries from the local geosite.dat /
		// geoip.dat that geo-refresh populates. Used by the LuCI Rule
		// Provider picker to populate its dropdown without the user
		// guessing valid category names.
		need(3)
		kind := os.Args[2]
		c, _ := m.Load()
		dir := c.Settings.GeoRefreshGeoIPDir
		if dir == "" {
			dir = "/etc/purewrt/geo"
		}
		var items []string
		var err error
		switch kind {
		case "geosite":
			items, err = geodb.ListGeoSiteEntries(dir + "/geosite.dat")
		case "geoip":
			items, err = geodb.ListGeoIPEntries(dir + "/geoip.dat")
		default:
			fmt.Fprintln(os.Stderr, "usage: purewrt geo-list <geosite|geoip>")
			os.Exit(2)
		}
		fatal(err)
		printJSON(items)
	case "geo-extract":
		// Dump the materialized rules for one category — useful for
		// debugging (`purewrt geo-extract geosite youtube | head`).
		need(4)
		kind, target := os.Args[2], os.Args[3]
		c, _ := m.Load()
		rp := config.RuleProvider{Format: kind, GeoTarget: target, Section: "common", Name: "geo-extract"}
		prov, err := provider.ParseGeoProvider(c, rp)
		fatal(err)
		printJSON(prov)
	case "zapret-autotune":
		need(3)
		opts := manager.ZapretAutotuneOptions{
			Hosts:       os.Args[2:],
			EnableHTTP:  true,
			EnableTLS12: true,
			EnableTLS13: true,
			EnableHTTP3: true,
			ScanLevel:   "standard",
			WriteUCI:    true,
		}
		res, err := m.ZapretAutotune(opts)
		fatal(err)
		fmt.Printf("zapret-autotune: hosts=%v\n", res.Hosts)
		fmt.Printf("  per-host winners: %d\n", len(res.PerHost))
		fmt.Printf("  COMMON intersection strategies: %d\n", len(res.Common))
		fmt.Printf("  materialized UCI strategies: %d\n", len(res.Strategies))
		for _, zs := range res.Strategies {
			fmt.Printf("    %s: %s\n", zs.Name, zs.Params)
		}
		if res.TranscriptPath != "" {
			fmt.Printf("  transcript: %s\n", res.TranscriptPath)
		}
	case "zapret-check":
		need(3)
		opt := manager.ZapretCheckOptions{}
		if len(os.Args) > 3 {
			opt.Interface = os.Args[3]
		}
		if len(os.Args) > 4 {
			opt.ScanLevel = os.Args[4]
		}
		if len(os.Args) > 5 {
			opt.Repeats = os.Args[5]
		}
		if len(os.Args) > 6 {
			opt.HTTP = os.Args[6]
		}
		if len(os.Args) > 7 {
			opt.TLS12 = os.Args[7]
		}
		if len(os.Args) > 8 {
			opt.TLS13 = os.Args[8]
		}
		if len(os.Args) > 9 {
			opt.HTTP3 = os.Args[9]
		}
		if len(os.Args) > 10 {
			opt.HTTPSGet = os.Args[10]
		}
		if os.Getenv("PUREWRT_ZAPRET_CHECK_STREAM") == "1" {
			fatal(m.ZapretCheckStrategyWithOptionsWriter(os.Args[2], opt, os.Stdout))
			return
		}
		out, err := m.ZapretCheckStrategyWithOptions(os.Args[2], opt)
		if out != "" {
			fmt.Print(out)
		}
		fatal(err)
	case "disable":
		fatal(m.Disable())
		fmt.Println("PureWRT generated routing/DNS changes removed")
	default:
		usage()
		os.Exit(2)
	}
}

func commandLogger(m manager.Manager) logging.Logger {
	c, err := m.Load()
	if err != nil {
		return logging.New("warn")
	}
	return logging.New(c.Settings.LogLevel)
}

// acquireBlocking waits up to operationLockMaxWait for the global purewrt
// operation lock. Previously withOperationLock used TryAcquire and exited
// with "purewrt operation already running" on contention, which meant a
// cron-triggered update overlapping with a LuCI save would drop the user's
// requested apply on the floor. Now we queue: the second caller blocks
// until the lock is free, then runs. Exits fatally on timeout so an actually
// stuck holder still gets surfaced instead of waiting forever.
func acquireBlocking() *system.Lock {
	deadline := time.Now().Add(operationLockMaxWait)
	for {
		lock, err := system.TryAcquire(operationLockPath)
		if err == nil {
			return lock
		}
		if !errors.Is(err, system.ErrLockBusy) {
			fatal(err)
		}
		if time.Now().After(deadline) {
			fatal(fmt.Errorf("timed out after %s waiting for %s; another purewrt operation appears stuck", operationLockMaxWait, operationLockPath))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func withOperationLock(fn func()) {
	lock := acquireBlocking()
	defer func() { _ = lock.Close() }()
	fn()
}

// withOperationLockCoalesce is the wholesale-operation variant: it blocks
// like withOperationLock, but also dedupes concurrent invocations via
// /var/run/purewrt.dirty. Pattern:
//
//  1. Caller touches the dirty file before queuing for the lock.
//  2. The lock holder, after each run of fn(), checks the dirty file. If
//     a newer caller arrived during fn(), the holder clears the flag and
//     re-runs fn() once more on that caller's behalf (bounded by
//     operationCoalesceCap).
//  3. The new caller, once it finally gets the lock, sees a clean dirty
//     file and returns rc=0 without re-doing the same work.
//
// Use this only for "wholesale" subcommands whose fn() reads the latest
// state from disk on each run (update, reload/apply, import,
// update-if-needed). DO NOT use for per-name commands like
// update-rule-provider <name> where the dirty flag can't carry which name
// was meant and coalescing would lose work.
func withOperationLockCoalesce(fn func()) {
	_ = os.WriteFile(operationDirtyPath, []byte("1"), 0644)
	lock := acquireBlocking()
	defer func() { _ = lock.Close() }()
	if _, err := os.Stat(operationDirtyPath); os.IsNotExist(err) {
		// A previous holder caught us up — work is done.
		return
	}
	for range operationCoalesceCap {
		// Clear BEFORE running so any new request that arrives during
		// fn() re-creates the file and we pick it up on the next check.
		_ = os.Remove(operationDirtyPath)
		fn()
		if _, err := os.Stat(operationDirtyPath); os.IsNotExist(err) {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "warn: coalesce cap hit after %d iterations; leaving dirty marker for next caller\n", operationCoalesceCap)
}

func usage() {
	fmt.Println("usage: purewrt {analyze <url>|preview <url>|import <url> [--proxy-only]|classify <name> [url] [behavior] [format]|rule-provider-status|override <provider> key=value...|add-native-list <url> <section> [--priority=N]|wizard-reset|update [--force]|update-rule-provider <name>|update-proxy-provider <name>|update-if-needed [--force]|mihomo-check-update [alpha|stable]|mihomo-download|mihomo-update|mihomo-install-release <alpha|stable>|mihomo-revert-package|mihomo-auto-update|mihomo-status|mihomo-mixin-get|mihomo-mixin-set|mihomo-mixin-preview|updates-available [--force]|geo-list <geosite|geoip>|geo-extract <geosite|geoip> <name>|generate [--force]|generate-cache-status|cache-clean|prune-orphans [--dry-run]|apply [--force]|reload [--force]|status|statistics|stats|validate|export [--include-secrets]|import-config <file|->|proxy-groups|proxy-select <group> <node> [--no-drain]|proxy-delay-test <group>|doctor|zapret-check <domain> [interface]|client-traffic <IP> [--seconds=N|--live --max-seconds=N] [--json]|ipdb-status|ipdb-update|disable}")
}

// formatClientTrafficReport renders a ClientTrafficReport as a human-readable
// table — used by `purewrt client-traffic <IP>` when --json is NOT set.
// Sections are emitted in the order the user is most likely to scan: blocked
// flows first, rejection signals second, then DNS/SNI noise.
func formatClientTrafficReport(r manager.ClientTrafficReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Client traffic report — %s (sampled %ds)\n", r.ClientIP, r.Seconds)
	fmt.Fprintf(&b, "Total flows: %d", r.LatestFlow.TotalFlows)
	if r.LatestFlow.SkippedIPv6 > 0 {
		fmt.Fprintf(&b, "  (skipped %d IPv6 flows)", r.LatestFlow.SkippedIPv6)
	}
	b.WriteString("\n\n")

	// Group flows by status.
	var blocked, lopsided, healthy []manager.FlowSummary
	for _, f := range r.LatestFlow.Flows {
		switch {
		case f.Unreplied:
			blocked = append(blocked, f)
		case f.Lopsided:
			lopsided = append(lopsided, f)
		default:
			healthy = append(healthy, f)
		}
	}
	writeFlowSection(&b, "Likely blocked", blocked)
	writeFlowSection(&b, "Lopsided (one-sided traffic)", lopsided)

	if len(r.ICMPRej) > 0 {
		b.WriteString("Rejection signals (ICMP):\n")
		for _, ev := range r.ICMPRej {
			fmt.Fprintf(&b, "  %s → %s code %d (%s)", ev.From, ev.To, ev.Code, ev.CodeText)
			if ev.OriginalDest != "" {
				fmt.Fprintf(&b, "  orig dest %s/%s:%d", ev.OriginalProto, ev.OriginalDest, ev.OriginalPort)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(r.TCPResets) > 0 {
		b.WriteString("TCP RST events:\n")
		for _, ev := range r.TCPResets {
			fmt.Fprintf(&b, "  %s:%d → %s:%d (%s)\n", ev.From, ev.FromPort, ev.To, ev.ToPort, ev.Source)
		}
		b.WriteString("\n")
	}
	if len(r.QUICRetries) > 0 {
		b.WriteString("QUIC handshake retries (UDP/443 blocked?):\n")
		for _, ev := range r.QUICRetries {
			fmt.Fprintf(&b, "  %s:%d  %d initials in %ds with no reply\n", ev.Dest, ev.DestPort, ev.InitialCount, ev.WindowSeconds)
		}
		b.WriteString("\n")
	}
	if len(r.SNIs) > 0 {
		fmt.Fprintf(&b, "TLS/QUIC SNIs observed: %d\n", len(r.SNIs))
	}
	writeFlowSection(&b, "Healthy flows", healthy)
	if len(r.DNSQueries) > 0 {
		fmt.Fprintf(&b, "DNS queries (last %d):\n", len(r.DNSQueries))
		shown := r.DNSQueries
		if len(shown) > 15 {
			shown = shown[len(shown)-15:]
		}
		for _, q := range shown {
			fmt.Fprintf(&b, "  %s %s\n", q.QType, q.Hostname)
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return b.String()
}

func writeFlowSection(b *strings.Builder, title string, flows []manager.FlowSummary) {
	if len(flows) == 0 {
		return
	}
	fmt.Fprintf(b, "%s (%d):\n", title, len(flows))
	for _, f := range flows {
		state := f.State
		if state == "" {
			state = "—"
		}
		host := f.Hostname
		if host == "" {
			host = "(unknown)"
		}
		fmt.Fprintf(b, "  %-3s %-15s :%-5d  pkts %4d/%-4d  bytes %7d/%-7d  %-12s  %s\n",
			f.Proto, f.DestIP, f.DestPort,
			f.OrigPackets, f.ReplyPackets,
			f.OrigBytes, f.ReplyBytes,
			state, host)
	}
	b.WriteString("\n")
}
func need(n int) {
	if len(os.Args) < n {
		usage()
		os.Exit(2)
	}
}
// exitPartialUpdate is the exit code for soft-continue update failures —
// still non-zero so the init-script retry loop and cron error paths fire
// unchanged, but distinct from hard failures (1) and usage errors (2,
// via need()) so operators can tell "retry will heal" from "never ran".
const exitPartialUpdate = 3

func exitCodeFor(err error) int {
	if errors.Is(err, manager.ErrPartialUpdate) {
		return exitPartialUpdate
	}
	return 1
}

func fatal(err error) {
	if err == nil {
		return
	}
	code := exitCodeFor(err)
	prefix := "error:"
	if code == exitPartialUpdate {
		// Part of the update succeeded and previous artifacts keep
		// serving — a warning, not a hard error.
		prefix = "warning:"
	}
	fmt.Fprintln(os.Stderr, prefix, err)
	os.Exit(code)
}
