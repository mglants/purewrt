package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/purewrt/purewrt/internal/checker"
	"github.com/purewrt/purewrt/internal/config"
	"github.com/purewrt/purewrt/internal/system"
)

// checkMain is the purewrt-check entry point — the binary installs as a
// symlink to purewrt and main() dispatches here on argv[0].
func checkMain() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: purewrt-check <domain-or-IP> [tcp|udp] [port] [WAN-device]")
		os.Exit(2)
	}
	query := os.Args[1]
	flow := checker.Flow{}
	if len(os.Args) > 2 {
		flow.Protocol = strings.ToLower(os.Args[2])
	}
	if len(os.Args) > 3 && os.Args[3] != "" {
		n, err := strconv.Atoi(os.Args[3])
		if err != nil || n < 1 {
			fmt.Fprintln(os.Stderr, "invalid destination port")
			os.Exit(2)
		}
		flow.Port = n
	}
	if len(os.Args) > 4 {
		flow.WAN = os.Args[4]
	}
	if err := flow.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	c, err := config.Load("/etc/config/purewrt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dns := checker.Resolve(query)
	trace := checker.TraceDestination(c, query, flow)
	var b strings.Builder
	fmt.Fprintf(&b, "Destination: %s\nProtocol: %s; port: %s; WAN device: %s\n", query, orNA(flow.Protocol), portLabel(flow.Port), orNA(flow.WAN))
	b.WriteString("Scope: destination rules only. Client assignments, local/DNS exemptions, existing marks/connection state and native provider expressions are not simulated.\n")
	b.WriteString("List matches predict scope; live DNS/nftset population and selected WAN can change the result.\n\n")
	fmt.Fprintf(&b, "DNS:\n  A: %v\n  AAAA: %v\n  error: %s\n\n", dns.A, dns.AAAA, dns.Error)
	b.WriteString("Destination rule trace (global exclusions, then section priority):\n")
	for _, warning := range trace.Warnings {
		fmt.Fprintf(&b, "  Warning: %s\n", warning)
	}
	for _, step := range trace.Steps {
		fmt.Fprintf(&b, "  [%s] %s (priority %d, %s), providers: %s\n    %s\n", step.Status, step.Section, step.Priority, step.Action, strings.Join(step.Providers, ", "), step.Reason)
	}
	if len(trace.Steps) == 0 {
		b.WriteString("  No destination-list matches.\n")
	}
	fmt.Fprintf(&b, "  Result: %s", trace.Action)
	if trace.Section != "" {
		fmt.Fprintf(&b, " via section %s", trace.Section)
	}
	b.WriteString("\n  If no destination rule matches this flow, it continues direct.\n")
	_, nftErr := (system.Runner{}).Run("nft", "list", "table", "inet", "purewrt")
	if nftErr != nil {
		fmt.Fprintf(&b, "\nLive destination sets unavailable: %v\n", nftErr)
	}
	for _, ip := range append(dns.A, dns.AAAA...) {
		if nftErr != nil {
			break
		}
		r := checker.ClassifyIPFlow(c, ip, flow)
		fmt.Fprintf(&b, "\nLive destination sets for %s: %s\n", ip, ipRouteDesc(r))
		for _, step := range r.Steps {
			fmt.Fprintf(&b, "  [%s] %s (priority %d): %s\n", step.Status, step.Section, step.Priority, step.Reason)
		}
	}
	// Do not report an actual selected route from an unresolved conditional scope.
	if trace.Action == "proxy" {
		if sec, ok := c.SectionByName(trace.Section); ok {
			b.WriteString("\nCandidate proxy path:\n")
			writeMihomo(&b, checker.MihomoForSection(c, sec))
		}
	}
	mw := checker.Mwan3(c)
	fmt.Fprintf(&b, "\nMwan3 installed: %v\nDirect traffic: %s\nProxy outbound: %s\n", mw.Installed, mw.DirectTraffic, mw.ProxyOutbound)
	fmt.Print(b.String())
}
func portLabel(port int) string {
	if port == 0 {
		return "unspecified"
	}
	return strconv.Itoa(port)
}

func writeMihomo(b *strings.Builder, mh checker.MihomoPath) {
	fmt.Fprintf(b, "Mihomo:\n  inbound: %s\n  group: %s\n  type: %s\n", mh.Inbound, mh.Group, orNA(mh.GroupType))
	if mh.GroupType == "load-balance" && mh.Strategy != "" {
		fmt.Fprintf(b, "  strategy: %s\n", mh.Strategy)
	}
	if mh.Filter != "" {
		fmt.Fprintf(b, "  filter: %s\n", mh.Filter)
	}
	fmt.Fprintf(b, "  pool: providers=%s vpns=%s\n", listOrNone(mh.Providers), listOrNone(mh.VPNs))
	if !mh.Reachable {
		fmt.Fprintf(b, "  selected node: unknown\n  node status: unknown (%s)\n\n", orNA(mh.Note))
		return
	}
	if mh.SelectedNode == "" && isLoadBalance(mh.GroupType) {
		fmt.Fprintf(b, "  selected node: n/a (load-balance — chosen per connection)\n")
	} else {
		fmt.Fprintf(b, "  selected node: %s\n  node status: %s\n", orNA(mh.SelectedNode), nodeStatus(mh.SelectedAlive, mh.SelectedDelayMS))
	}
	fmt.Fprintf(b, "  members (%d):\n", len(mh.Members))
	for _, m := range mh.Members {
		fmt.Fprintf(b, "    - %s  %s\n", m.Name, nodeStatus(m.Alive, m.DelayMS))
	}
	if mh.Note != "" {
		fmt.Fprintf(b, "  note: %s\n", mh.Note)
	}
	b.WriteString("\n")
}

// isLoadBalance matches both the config value ("load-balance") and mihomo's
// live API value ("LoadBalance").
func isLoadBalance(t string) bool {
	return strings.Contains(strings.ToLower(strings.ReplaceAll(t, "-", "")), "loadbalance")
}

func nodeStatus(alive bool, delayMS int) string {
	if alive {
		if delayMS > 0 {
			return fmt.Sprintf("alive, %dms", delayMS)
		}
		return "alive"
	}
	return "down/untested"
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	return "[" + strings.Join(s, " ") + "]"
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

// ipRouteDesc renders the effective IP route: the set + section/action, or a
// plain "default route (kernel direct)" when the IP is in no routing set.
func ipRouteDesc(r checker.IPRoute) string {
	if r.Set == "" || r.Action == "default" {
		return "default route (kernel direct)"
	}
	if r.Section == "bypass" || r.Section == "direct" || r.Section == "reject" {
		return fmt.Sprintf("%s (%s)", r.Set, r.Action)
	}
	return fmt.Sprintf("%s → section %q (%s)", r.Set, r.Section, r.Action)
}
