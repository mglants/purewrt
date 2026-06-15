package checker

import (
	"strings"

	"github.com/purewrt/purewrt/internal/system"
)

type commandRunner interface {
	Run(name string, args ...string) (string, error)
}

func NFTSetContains(set, ip string) (bool, string) {
	return nftSetContainsWithRunner(system.Runner{}, set, ip)
}

func nftSetContainsWithRunner(r commandRunner, set, ip string) (bool, string) {
	out, err := r.Run("nft", "get", "element", "inet", "purewrt", set, "{", ip, "}")
	if err != nil {
		return false, out
	}
	return strings.Contains(out, ip), out
}
