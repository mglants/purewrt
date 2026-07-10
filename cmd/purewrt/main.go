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
	"path/filepath"
	"runtime/debug"
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

// cliGCPercent is the GC target for the short-lived CLI. Generation wall
// time on ARM routers is GC-pacing-bound: default GOGC measured erratic
// 0.3–10 s per `generate --force` on a cortex-a53 (80 k-domain config)
// where 800 gave a flat 0.12 s, for +1.2 MB peak RSS — live heap stays
// tiny because rule providers stream. Long-lived daemons (purewrt-api)
// must NOT adopt this: their heap ceiling matters more than latency.
const cliGCPercent = 800

// tuneGC applies cliGCPercent unless the user set GOGC themselves — an
// explicit env var (including GOGC=off) always wins.
func tuneGC() {
	if _, ok := os.LookupEnv("GOGC"); ok {
		return
	}
	debug.SetGCPercent(cliGCPercent)
}

// multiCallEntry maps an argv[0] basename to a dedicated entry point.
// purewrt-check and purewrt-api install as symlinks to the purewrt binary
// (three separate Go binaries duplicated ~13MB of runtime/stdlib on flash);
// anything unrecognized falls through to the regular CLI so renamed copies
// (e.g. the purewrt-new scp temp name from the deploy recipe) still work.
func multiCallEntry(argv0 string) string {
	switch argv0 {
	case "purewrt-check":
		return "check"
	case "purewrt-api":
		return "api"
	}
	return ""
}

func main() {
	switch multiCallEntry(filepath.Base(os.Args[0])) {
	case "check":
		tuneGC() // short-lived like the CLI — same GC trade applies
		checkMain()
		return
	case "api":
		apiMain()
		return
	}
	tuneGC()
	m := manager.Manager{}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		topic := ""
		if len(os.Args) > 2 {
			topic = os.Args[2]
		}
		help(topic)
		return
	}
	c, ok := lookupCommand(cmd)
	if !ok {
		fmt.Fprintf(os.Stderr, "purewrt: unknown command %q\nRun 'purewrt help' for the command list.\n", cmd)
		os.Exit(2)
	}
	log := commandLogger(m)
	defer log.DebugTimer("command: %s", cmd)()
	log.Debug("command: %s start", cmd)
	c.run(m)
}

// command is one CLI subcommand: its canonical name, display metadata for
// `purewrt help`, and the handler. Handlers read os.Args directly (the
// pre-registry switch did the same) and exit via fatal()/os.Exit.
type command struct {
	name    string
	aliases []string
	group   string
	args    string
	desc    string
	run     func(m manager.Manager)
}

// groupOrder fixes the section order of `purewrt help`.
var groupOrder = []string{
	"Subscriptions & providers",
	"Generate & apply",
	"Status & diagnostics",
	"Mihomo & proxies",
	"Zapret (DPI bypass)",
	"Geo & IP databases",
	"Config import/export",
	"OONI",
	"System",
}

func lookupCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
		for _, a := range c.aliases {
			if a == name {
				return c, true
			}
		}
	}
	return command{}, false
}

// help prints the grouped command list, or one command's synopsis when a
// topic is given (`purewrt help apply`).
func help(topic string) {
	if topic != "" {
		c, ok := lookupCommand(topic)
		if !ok {
			fmt.Fprintf(os.Stderr, "purewrt: unknown command %q\nRun 'purewrt help' for the command list.\n", topic)
			os.Exit(2)
		}
		fmt.Printf("usage: purewrt %s", c.name)
		if c.args != "" {
			fmt.Printf(" %s", c.args)
		}
		fmt.Println()
		if len(c.aliases) > 0 {
			fmt.Printf("alias: %s\n", strings.Join(c.aliases, ", "))
		}
		fmt.Printf("\n%s\n", c.desc)
		return
	}
	fmt.Println("usage: purewrt <command> [args]")
	fmt.Println("       purewrt help <command>   detailed synopsis for one command")
	for _, g := range groupOrder {
		printed := false
		for _, c := range commands {
			if c.group != g {
				continue
			}
			if !printed {
				fmt.Printf("\n%s:\n", g)
				printed = true
			}
			name := c.name
			if len(c.aliases) > 0 {
				name += " (" + strings.Join(c.aliases, ", ") + ")"
			}
			fmt.Printf("  %-26s %s\n", name, c.desc)
		}
	}
}

var commands = []command{
	{name: "analyze", group: "Subscriptions & providers",
		args: "<url>",
		desc: "Fetch a subscription and print its classification as JSON",
		run: func(m manager.Manager) {
			need(3)
			a, err := m.Analyze(os.Args[2])
			fatal(err)
			b, _ := json.MarshalIndent(a, "", "  ")
			fmt.Println(string(b))
		}},
	{name: "import", group: "Subscriptions & providers",
		args: "<url> [--proxy-only]",
		desc: "Import a subscription, update providers and apply",
		run: func(m manager.Manager) {
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
		}},
	{name: "preview", aliases: []string{"diff"}, group: "Subscriptions & providers",
		args: "<url>",
		desc: "Show what importing a subscription would change",
		run: func(m manager.Manager) {
			need(3)
			out, err := m.Preview(os.Args[2])
			fatal(err)
			fmt.Println(out)
		}},
	{name: "classify", group: "Subscriptions & providers",
		args: "<name> [url] [behavior] [format]",
		desc: "Classify a provider payload (rule set, proxy list, ...)",
		run: func(m manager.Manager) {
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
		}},
	{name: "rule-provider-status", group: "Subscriptions & providers",
		args: "",
		desc: "JSON status of every rule provider",
		run: func(m manager.Manager) {
			out, err := m.RuleProviderStatusJSON()
			fatal(err)
			fmt.Println(out)
		}},
	{name: "override", group: "Subscriptions & providers",
		args: "<provider> key=value...",
		desc: "Persist manual overrides for a rule provider",
		run: func(m manager.Manager) {
			need(4)
			fatal(m.OverrideRuleProvider(os.Args[2], os.Args[3:]))
			fmt.Println("override saved")
		}},
	{name: "add-native-list", group: "Subscriptions & providers",
		args: "<url> <section> [--no-apply] [--priority=N]",
		desc: "Register a pre-built nftset list as a native provider",
		run: func(m manager.Manager) {
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
		}},
	{name: "wizard-reset", group: "Config import/export",
		args: "",
		desc: "Reset config to defaults (VPN/Zapret/credentials preserved)",
		run: func(m manager.Manager) {
			// Flush config to defaults, preserving VPN/Zapret + credentials +
			// mihomo binary selection. Used by the wizard's "start over" apply.
			fatal(m.WizardReset())
			fmt.Println("config reset (VPN/Zapret/credentials preserved)")
		}},
	{name: "default-lists-catalog", group: "Subscriptions & providers",
		args: "",
		desc: "Fetch the purewrt-lists catalog JSON",
		run: func(m manager.Manager) {
			// Fetch <default_lists_base_url>/catalog.json via the bootstrap client.
			out, err := m.DefaultListsCatalog()
			fatal(err)
			os.Stdout.Write(out)
		}},
	{name: "update", group: "Subscriptions & providers",
		args: "[--force]",
		desc: "Update all providers and rule providers",
		run: func(m manager.Manager) {
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
		}},
	{name: "update-rule-provider", group: "Subscriptions & providers",
		args: "<name> [--no-restart]",
		desc: "Update one rule provider (--no-restart hot-reloads mihomo)",
		run: func(m manager.Manager) {
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
		}},
	{name: "update-proxy-provider", group: "Subscriptions & providers",
		args: "<name>",
		desc: "Update one proxy provider and apply if changed",
		run: func(m manager.Manager) {
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
		}},
	{name: "update-if-needed", group: "Subscriptions & providers",
		args: "[--force]",
		desc: "Update providers, then apply only when something changed",
		run: func(m manager.Manager) {
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
		}},
	{name: "mihomo-check-update", group: "Mihomo & proxies",
		args: "[alpha|stable]",
		desc: "Check GitHub for a newer mihomo release",
		run: func(m manager.Manager) {
			// Optional positional arg: channel (alpha|stable). Defaults to
			// the configured channel (alpha for legacy installs).
			channel := ""
			if len(os.Args) > 2 {
				channel = os.Args[2]
			}
			info, err := m.MihomoCheckUpdateChannel(channel)
			fatal(err)
			printJSON(info)
		}},
	{name: "mihomo-download", aliases: []string{"mihomo-update"}, group: "Mihomo & proxies",
		args: "",
		desc: "Report availability of a mihomo-alpha package update",
		run: func(m manager.Manager) {
			info, err := m.MihomoPackageUpdate()
			fatal(err)
			fmt.Printf("mihomo-alpha package update available: %s (%s). Rebuild/install the bundled mihomo-alpha package; binary overwrite is disabled.\n", info.Version, info.AssetName)
		}},
	{name: "mihomo-install-release", group: "Mihomo & proxies",
		args: "<alpha|stable>",
		desc: "Download, verify and install a mihomo release binary",
		run: func(m manager.Manager) {
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
		}},
	{name: "mihomo-revert-package", group: "Mihomo & proxies",
		args: "",
		desc: "Revert to the package-installed mihomo binary",
		run: func(m manager.Manager) {
			fatal(m.MihomoRevertToPackage())
			fmt.Println("reverted to package-installed mihomo; restarted")
		}},
	{name: "mihomo-auto-update", group: "Mihomo & proxies",
		args: "",
		desc: "Cron entry: install a newer mihomo when available",
		run: func(m manager.Manager) {
			// Cron entry — quiet on the happy path, loud on action. The
			// init script's cron block pipes our stdout through logger so
			// every tick lands in syslog under purewrt-cron, even the
			// up-to-date ones — useful for confirming the schedule fires.
			res, err := m.MihomoAutoUpdate()
			if err != nil {
				fmt.Fprintln(os.Stderr, "mihomo-auto-update:", err)
			}
			printJSON(res)
		}},
	{name: "mihomo-status", group: "Mihomo & proxies",
		args: "",
		desc: "JSON status of the mihomo binary/service",
		run: func(m manager.Manager) {
			printJSON(m.MihomoStatus())
		}},
	{name: "mihomo-mixin-get", group: "Mihomo & proxies",
		args: "",
		desc: "Print the user mixin and merge status",
		run: func(m manager.Manager) {
			info, err := m.MihomoMixinRead()
			fatal(err)
			printJSON(info)
		}},
	{name: "mihomo-mixin-set", group: "Mihomo & proxies",
		args: "",
		desc: "Write the user mixin from stdin (empty clears it)",
		run: func(m manager.Manager) {
			// Mixin body comes from stdin; the rpcd dispatcher pipes the
			// JSON body's `body` field through. Empty stdin → delete the
			// mixin file (deliberate "clear" gesture).
			body, _ := io.ReadAll(os.Stdin)
			fatal(m.MihomoMixinWrite(string(body)))
			fmt.Println("ok")
		}},
	{name: "mihomo-mixin-preview", group: "Mihomo & proxies",
		args: "",
		desc: "Preview the merged mihomo config for a mixin from stdin",
		run: func(m manager.Manager) {
			body, _ := io.ReadAll(os.Stdin)
			out, err := m.MihomoMixinPreview(string(body))
			fatal(err)
			fmt.Print(out)
		}},
	{name: "updates-available", group: "System",
		args: "[--force]",
		desc: "List available package updates",
		run: func(m manager.Manager) {
			force := len(os.Args) > 2 && os.Args[2] == "--force"
			updates, err := m.AptUpdatesAvailable(force)
			fatal(err)
			printJSON(updates)
		}},
	{name: "generate", group: "Generate & apply",
		args: "[--force]",
		desc: "Render mihomo/dnsmasq/nftables artifacts",
		run: func(m manager.Manager) {
			force := len(os.Args) > 2 && os.Args[2] == "--force"
			fatal(m.GenerateWithOptions(force))
			fmt.Println("generated mihomo, dnsmasq and nftables config")
		}},
	{name: "generate-cache-status", group: "Generate & apply",
		args: "",
		desc: "Show the generation fingerprint cache status",
		run: func(m manager.Manager) {
			out, err := m.GenerateCacheStatus()
			fatal(err)
			fmt.Print(out)
		}},
	{name: "cache-clean", group: "Generate & apply",
		args: "",
		desc: "Remove the rule artifact cache",
		run: func(m manager.Manager) {
			fatal(m.CacheClean())
			fmt.Println("PureWRT rule artifact cache removed")
		}},
	{name: "prune-orphans", group: "Generate & apply",
		args: "[--dry-run]",
		desc: "Remove provider files with no configured provider",
		run: func(m manager.Manager) {
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
		}},
	{name: "apply", aliases: []string{"reload"}, group: "Generate & apply",
		args: "[--force]",
		desc: "Generate and apply the full configuration",
		run: func(m manager.Manager) {
			withOperationLockCoalesce(func() {
				force := len(os.Args) > 2 && os.Args[2] == "--force"
				fatal(m.ApplyWithOptions(force))
				fmt.Println("applied PureWRT safely")
			})
		}},
	{name: "status", group: "Status & diagnostics",
		args: "",
		desc: "Human-readable overall status",
		run: func(m manager.Manager) {
			fmt.Print(m.Status())
		}},
	{name: "statistics", aliases: []string{"stats"}, group: "Status & diagnostics",
		args: "",
		desc: "Traffic/ruleset statistics as JSON",
		run: func(m manager.Manager) {
			out, err := m.StatisticsJSON()
			fatal(err)
			fmt.Println(out)
		}},
	{name: "validate", group: "Generate & apply",
		args: "",
		desc: "Validate the configuration without applying",
		run: func(m manager.Manager) {
			fatal(m.Validate())
			fmt.Println("validation OK")
		}},
	{name: "proxy-groups", group: "Mihomo & proxies",
		args: "",
		desc: "JSON list of proxy groups with member health",
		run: func(m manager.Manager) {
			// JSON array of mihomo proxy groups with member health. The rpcd
			// dispatcher wraps it in {items:[...]} (ubus rejects bare arrays).
			groups, err := m.ProxyGroups()
			fatal(err)
			printJSON(groups)
		}},
	{name: "proxy-select", group: "Mihomo & proxies",
		args: "<group> <node> [--no-drain]",
		desc: "Select a node in a proxy group",
		run: func(m manager.Manager) {
			need(4)
			drain := !(len(os.Args) > 4 && os.Args[4] == "--no-drain")
			res, err := m.ProxySelect(os.Args[2], os.Args[3], drain)
			fatal(err)
			printJSON(res)
		}},
	{name: "proxy-delay-test", group: "Mihomo & proxies",
		args: "<group>",
		desc: "Latency-test every node in a group",
		run: func(m manager.Manager) {
			need(3)
			delays, err := m.ProxyDelayTest(os.Args[2])
			fatal(err)
			printJSON(delays)
		}},
	{name: "export", group: "Config import/export",
		args: "[--include-secrets]",
		desc: "Dump the config as portable UCI text (secrets redacted)",
		run: func(m manager.Manager) {
			// Portable UCI-text dump of the full config. Secrets (controller
			// secret, subscription tokens in URLs, HWIDs) are redacted unless
			// --include-secrets is passed — exports get pasted into issues.
			includeSecrets := len(os.Args) > 2 && os.Args[2] == "--include-secrets"
			out, err := m.ExportConfig(includeSecrets)
			fatal(err)
			fmt.Print(out)
		}},
	{name: "import-config", group: "Config import/export",
		args: "<file|->",
		desc: "Validate and replace the config (never applies)",
		run: func(m manager.Manager) {
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
		}},
	{name: "doctor", group: "Status & diagnostics",
		args: "[--canaries [--report] [host:port...]] [--json]",
		desc: "Run system health checks",
		run: func(m manager.Manager) {
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
		}},
	{name: "resolvers-probe", group: "Status & diagnostics",
		args: "[canary] [--json]",
		desc: "Probe each DNS resolver in the pool",
		run: func(m manager.Manager) {
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
		}},
	{name: "inspect-ipv6", group: "Status & diagnostics",
		args: "",
		desc: "JSON report of IPv6 routing state",
		run: func(m manager.Manager) {
			printJSON(m.InspectIPv6())
		}},
	{name: "dpi-check", group: "Status & diagnostics",
		args: "<host> [--ip=<ipv4>] [--timeout=<sec>] [--json]",
		desc: "TCP-16-20 DPI matrix probe (takes ~2 min)",
		run: func(m manager.Manager) {
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
		}},
	{name: "net-check", group: "Status & diagnostics",
		args: "[--bytes=N] [--timeout=SEC] [--domain=D] [--per-node] [--json]",
		desc: "Layered connectivity diagnostic through the proxy",
		run: func(m manager.Manager) {
			// Layered, topology-aware connectivity diagnostic: drives real bytes
			// through the proxy mixed-port + isolates mihomo/routing/WAN, records
			// throughput/verdict metrics. Usage:
			//   purewrt net-check [--bytes=N] [--timeout=SEC] [--domain=D] [--per-node] [--json]
			args, asJSON := stripJSONFlag(os.Args[2:])
			opts := manager.NetCheckOpts{}
			for _, a := range args {
				switch {
				case a == "--per-node":
					opts.PerNode = true
				case strings.HasPrefix(a, "--bytes="):
					if n, err := strconv.ParseInt(strings.TrimPrefix(a, "--bytes="), 10, 64); err == nil && n > 0 {
						opts.Bytes = n
					}
				case strings.HasPrefix(a, "--timeout="):
					if n, err := strconv.Atoi(strings.TrimPrefix(a, "--timeout=")); err == nil && n > 0 {
						opts.Timeout = time.Duration(n) * time.Second
					}
				case strings.HasPrefix(a, "--domain="):
					opts.Domain = strings.TrimPrefix(a, "--domain=")
				}
			}
			overall := 90
			if opts.PerNode {
				overall = 300
			}
			ctx, cancel := contextWithTimeout(overall)
			defer cancel()
			rep := m.NetCheck(ctx, opts)
			if asJSON {
				printJSON(rep)
			} else {
				fmt.Print(manager.FormatNetCheck(rep))
			}
			if rep.Verdict != "ok" {
				os.Exit(1)
			}
		}},
	{name: "client-traffic", group: "Status & diagnostics",
		args: "<IP> [--seconds=N] [--live --max-seconds=N] [--json]",
		desc: "Diagnose one LAN client's flows (snapshot or live NDJSON)",
		run: func(m manager.Manager) {
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
		}},
	{name: "zapret-installed", group: "Zapret (DPI bypass)",
		args: "",
		desc: "Report whether zapret is installed (JSON)",
		run: func(m manager.Manager) {
			// Cheap stat-based check the LuCI side uses to gate Zapret-only
			// UI (logs panel, diagnostics section). Menu entry hiding is
			// driven by /usr/bin/nfqws's depends.fs, not by this method.
			printJSON(map[string]bool{"installed": m.ZapretInstalled()})
		}},
	{name: "zapret-status", group: "Zapret (DPI bypass)",
		args: "",
		desc: "Live nfqws2 status: running instances + queued traffic (JSON)",
		run: func(m manager.Manager) {
			printJSON(m.ZapretStatus())
		}},
	{name: "ooni-installed", group: "OONI",
		args: "",
		desc: "Report whether ooniprobe is installed (JSON)",
		run: func(m manager.Manager) {
			// Stat-based gate for the OONI LuCI page (ooniprobe is an optional
			// 25.12-only companion package).
			printJSON(map[string]bool{"installed": m.OONIInstalled()})
		}},
	{name: "ooni-status", group: "OONI",
		args: "",
		desc: "OONI measurement status (JSON)",
		run: func(m manager.Manager) {
			printJSON(m.OONIStatus())
		}},
	{name: "ooni-prepare", group: "OONI",
		args: "",
		desc: "Write ooniprobe home/config for the cron wrapper",
		run: func(m manager.Manager) {
			// Writes the ooniprobe home + config.json (informed consent + upload
			// flag), chowned to the ooni user. Invoked as root by the cron
			// wrapper before su-ing to the ooni user for the measurement.
			fatal(m.OONIPrepare())
		}},
	{name: "ipdb-status", group: "Geo & IP databases",
		args: "",
		desc: "ip2asn database status (JSON)",
		run: func(m manager.Manager) {
			// Cheap stat-only status; loadCount=false because the CLI is also
			// invoked from rpcd-driven LuCI poll where we want sub-100ms
			// response time. Path is derived from the user's configured
			// Workdir so non-default installs land in the right place.
			c, _ := m.Load()
			printJSON(ipdb.CheckStatus(ipdb.GZPath(c.Settings.Workdir), false))
		}},
	{name: "ipdb-asn", group: "Geo & IP databases",
		args: "<asn>",
		desc: "List all prefixes announced by an ASN",
		run: func(m manager.Manager) {
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
		}},
	{name: "ipdb-update", group: "Geo & IP databases",
		args: "",
		desc: "Download/refresh the ip2asn database",
		run: func(m manager.Manager) {
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
		}},
	{name: "doctor-warnings", group: "Status & diagnostics",
		args: "",
		desc: "Doctor warnings only (JSON)",
		run: func(m manager.Manager) {
			printJSON(m.DoctorWarnings())
		}},
	{name: "subscription-expiry", group: "Subscriptions & providers",
		args: "",
		desc: "Subscription expiry/quota info (JSON)",
		run: func(m manager.Manager) {
			printJSON(m.SubscriptionExpiry())
		}},
	{name: "mihomo-traffic-sample", group: "Mihomo & proxies",
		args: "",
		desc: "One up/down traffic sample from mihomo (JSON)",
		run: func(m manager.Manager) {
			s, err := m.MihomoTrafficSample()
			if err != nil {
				fmt.Fprintln(os.Stderr, "mihomo traffic:", err)
				os.Exit(1)
			}
			printJSON(s)
		}},
	{name: "zapret-compiled-opt", group: "Zapret (DPI bypass)",
		args: "",
		desc: "Print the generated upstream zapret config",
		run: func(m manager.Manager) {
			c, err := m.Load()
			fatal(err)
			fmt.Print(string(generator.ZapretUpstreamConfig(c)))
		}},
	{name: "zapret-restart", group: "Zapret (DPI bypass)",
		args: "",
		desc: "Restart the zapret service (upstream or legacy init)",
		run: func(m manager.Manager) {
			// Try upstream init first, then fall back to the legacy PureWRT one.
			// Errors are non-fatal so the rpcd caller always gets a uniform JSON.
			runFirstAvailable("/etc/init.d/zapret2", "/etc/init.d/purewrt-zapret")
		}},
	{name: "geo-refresh", group: "Geo & IP databases",
		args: "[--json]",
		desc: "Refresh geosite/geoip databases and reload mihomo",
		run: func(m manager.Manager) {
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
		}},
	{name: "flush-dns-sets", group: "Status & diagnostics",
		args: "[--json]",
		desc: "Flush the dynamic dns_* nftables sets",
		run: func(m manager.Manager) {
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
		}},
	{name: "geo-list", group: "Geo & IP databases",
		args: "<geosite|geoip>",
		desc: "List categories in the local geo databases",
		run: func(m manager.Manager) {
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
		}},
	{name: "geo-extract", group: "Geo & IP databases",
		args: "<geosite|geoip> <name>",
		desc: "Dump materialized rules for one geo category",
		run: func(m manager.Manager) {
			// Dump the materialized rules for one category — useful for
			// debugging (`purewrt geo-extract geosite youtube | head`).
			need(4)
			kind, target := os.Args[2], os.Args[3]
			c, _ := m.Load()
			rp := config.RuleProvider{Format: kind, GeoTarget: target, Section: "common", Name: "geo-extract"}
			prov, err := provider.ParseGeoProvider(c, rp)
			fatal(err)
			printJSON(prov)
		}},
	{name: "zapret-check", group: "Zapret (DPI bypass)",
		args: "<domain>... [iface] [scan] [repeats] [http] [tls12] [tls13] [http3] [https-get]",
		desc: "Run blockcheck2 against one or more domains",
		run: func(m manager.Manager) {
			// os.Args[2] is one or more whitespace-separated hosts (the merged
			// single-host + multi-host "autotune" blockcheck). 2+ hosts make
			// blockcheck2.sh emit a COMMON-intersection block.
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
		}},
	{name: "zapret-candidates", group: "Zapret (DPI bypass)",
		args: "[--update]",
		desc: "Print (optionally refresh) the strategy candidate list",
		run: func(m manager.Manager) {
			// zapret-candidates [--update] — print the resolved strategy candidate
			// list (embed / /etc override); --update fetches from purewrt-lists first.
			if len(os.Args) > 2 && os.Args[2] == "--update" {
				fatal(m.FetchZapretCandidates())
			}
			printJSON(config.LoadZapretCandidates())
		}},
	{name: "zapret-strategy-test", group: "Zapret (DPI bypass)",
		args: "<candidate> [iface] [--download] [--suite=dpi] [site...]",
		desc: "Probe one desync strategy candidate",
		run: func(m manager.Manager) {
			// zapret-strategy-test <candidate-name> [iface] [--download] [site...] —
			// probe one candidate through real nfqws2 desync; emits per-site verdicts.
			need(3)
			list := config.LoadZapretCandidates()
			var cand *config.ZapretCandidate
			for i := range list.Candidates {
				if list.Candidates[i].Name == os.Args[2] {
					cand = &list.Candidates[i]
					break
				}
			}
			if cand == nil {
				fatal(fmt.Errorf("unknown candidate %q", os.Args[2]))
			}
			opt := manager.ZapretStrategyTestOptions{CmdOpts: cand.Params, Blobs: cand.Blobs}
			haveIface := false
			for _, a := range os.Args[3:] {
				switch {
				case a == "--download":
					opt.Download = true
				case a == "--suite=dpi":
					s, err := m.DPISuiteSites()
					fatal(err)
					opt.Sites = append(opt.Sites, s...)
				case !haveIface:
					opt.Interface = a
					haveIface = true
				default:
					opt.Sites = append(opt.Sites, a)
				}
			}
			res, err := m.ZapretStrategyTest(opt)
			fatal(err)
			printJSON(res)
		}},
	{name: "zapret-strategy-sweep", group: "Zapret (DPI bypass)",
		args: "[iface] [--isp=<label>] [--service=<label>] [--name=<candidate>] [--download] [--suite=dpi] [site...]",
		desc: "Test every candidate, streaming ranked results",
		run: func(m manager.Manager) {
			// zapret-strategy-sweep [iface] [--isp=<label>] [--service=<label>] [--name=<candidate>] [--download] [site...] —
			// test candidates (filtered by ISP/service, or one by --name), ranked.
			// --name lets LuCI's "Test selected" reuse this bg-job path instead of
			// a synchronous single-test rpc (which times out the XHR).
			iface := ""
			isp := ""
			service := ""
			name := ""
			download := false
			haveIface := false
			var sites []string
			for _, a := range os.Args[2:] {
				switch {
				case strings.HasPrefix(a, "--isp="):
					isp = strings.TrimPrefix(a, "--isp=")
				case strings.HasPrefix(a, "--service="):
					service = strings.TrimPrefix(a, "--service=")
				case strings.HasPrefix(a, "--name="):
					name = strings.TrimPrefix(a, "--name=")
				case a == "--download":
					download = true
				case a == "--suite=dpi":
					s, err := m.DPISuiteSites()
					fatal(err)
					sites = append(sites, s...)
				case !haveIface:
					iface = a
					haveIface = true
				default:
					sites = append(sites, a)
				}
			}
			// Stream one JSON object per line as each candidate finishes, so the
			// LuCI poller shows results incrementally instead of waiting for the
			// whole sweep. os.Stdout is unbuffered (an *os.File) → each line lands
			// in the bg-job log immediately.
			enc := json.NewEncoder(os.Stdout)
			m.ZapretStrategySweepStream(iface, sites, isp, service, name, download, func(res manager.ZapretStrategyTestResult) {
				_ = enc.Encode(res)
			})
		}},
	{name: "zapret-test-sites", group: "Zapret (DPI bypass)",
		args: "[--update]",
		desc: "Print (optionally refresh) the probe-target site suite",
		run: func(m manager.Manager) {
			// zapret-test-sites [--update] — print the resolved probe-target suite;
			// --update fetches it from purewrt-lists first.
			if len(os.Args) > 2 && os.Args[2] == "--update" {
				fatal(m.FetchZapretTestSites())
			}
			printJSON(config.LoadZapretTestSites())
		}},
	{name: "zapret-dpi-suite", group: "Zapret (DPI bypass)",
		args: "[--update]",
		desc: "Print (optionally refresh) the DPI-checkers host suite",
		run: func(m manager.Manager) {
			// zapret-dpi-suite [--update] — print the DPI-checkers probe hosts;
			// --update re-fetches from hyperion-cs/dpi-checkers.
			if len(os.Args) > 2 && os.Args[2] == "--update" {
				s, err := m.FetchDPISuite()
				fatal(err)
				printJSON(s)
			} else {
				s, err := m.DPISuiteSites()
				fatal(err)
				printJSON(s)
			}
		}},
	{name: "disable", group: "Generate & apply",
		args: "",
		desc: "Remove all generated routing/DNS changes",
		run: func(m manager.Manager) {
			fatal(m.Disable())
			fmt.Println("PureWRT generated routing/DNS changes removed")
		}},
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
	fmt.Println("usage: purewrt <command> [args]   —   run 'purewrt help' for the command list")
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
