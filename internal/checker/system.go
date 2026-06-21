package checker

import (
	"github.com/purewrt/purewrt/internal/system"
)

type commandRunner interface {
	Run(name string, args ...string) (string, error)
}

func NFTSetContains(set, ip string) (bool, string) {
	return nftSetContainsWithRunner(system.Runner{}, set, ip)
}

func nftSetContainsWithRunner(r commandRunner, set, ip string) (bool, string) {
	// `nft get element` is interval-aware: on an `flags interval` set (the
	// section sets, which hold CIDRs from IP-CIDR rule providers) it succeeds
	// when the queried IP is *covered by a range*, exiting 0 and printing the
	// containing range (e.g. `5.9.0.0/16`) — NOT the queried IP. So membership
	// is the exit code, not a substring match: a `strings.Contains(out, ip)`
	// here would false-negative every CIDR match (the IP isn't in the range's
	// text). A genuinely-absent element exits non-zero ("Could not process
	// rule"). This correctly handles both interval sets and the exact-IP
	// dns_* sets (dnsmasq-populated).
	out, err := r.Run("nft", "get", "element", "inet", "purewrt", set, "{", ip, "}")
	return err == nil, out
}
