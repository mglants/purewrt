package manager

import (
	"encoding/json"
	"fmt"
	"github.com/purewrt/purewrt/internal/system"
	"os"
	"strconv"
	"strings"
)

const clientOffloadName = "purewrt_client_offload"

type clientOffloadRule struct{ Rule, Handle, Table, Definition string }

func clientOffloadFind(out string) (*clientOffloadRule, error) {
	var found *clientOffloadRule
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "flow add @") {
			continue
		}
		rule, handle, ok := strings.Cut(strings.TrimSpace(line), " # handle ")
		if !ok {
			return nil, fmt.Errorf("flow offload rule has no handle")
		}
		if _, e := strconv.ParseUint(handle, 10, 64); e != nil {
			return nil, e
		}
		if found != nil {
			return nil, fmt.Errorf("multiple flow-offload rules are not supported by the client tester")
		}
		f := strings.Fields(rule)
		table := ""
		for i := 0; i+2 < len(f); i++ {
			if f[i] == "flow" && f[i+1] == "add" {
				table = strings.TrimPrefix(f[i+2], "@")
				break
			}
		}
		if !safeIdentRE.MatchString(table) {
			return nil, fmt.Errorf("unsupported flowtable name")
		}
		found = &clientOffloadRule{Rule: rule, Handle: handle, Table: table}
	}
	return found, nil
}
func clientOffloadNFT(rule *clientOffloadRule, ip string) string {
	if rule == nil {
		return ""
	}
	return fmt.Sprintf(`add set inet fw4 %[1]s { type ipv4_addr; flags timeout; timeout 300s; elements = { %[2]s }; }
add chain inet fw4 %[1]s
add rule inet fw4 %[1]s ct original ip saddr @%[1]s return
replace rule inet fw4 forward handle %[4]s jump %[1]s comment "purewrt_client_test"
delete flowtable inet fw4 %[5]s
%[6]s
add rule inet fw4 %[1]s %[3]s
`, clientOffloadName, ip, rule.Rule, rule.Handle, rule.Table, rule.Definition)
}
func clientOffloadPrepare(r commandRunner, ip string) (string, *clientOffloadRule, error) {
	out, e := r.Run("nft", "-a", "list", "chain", "inet", "fw4", "forward")
	if e != nil {
		return "", nil, fmt.Errorf("cannot inspect firewall offloading: %w", e)
	}
	if strings.Contains(out, "jump "+clientOffloadName) {
		return "", nil, fmt.Errorf("stale client offload guard exists; stop the previous test first")
	}
	rule, e := clientOffloadFind(out)
	if e != nil {
		return "", nil, e
	}
	if rule == nil {
		_ = os.Remove(clientTestPath(".offload.json"))
		return "", nil, nil
	}
	definition, e := r.Run("nft", "list", "flowtable", "inet", "fw4", rule.Table)
	if e != nil {
		return "", nil, fmt.Errorf("snapshot flowtable: %w", e)
	}
	rule.Definition = definition
	b, _ := json.Marshal(rule)
	if e = system.AtomicWrite(clientTestPath(".offload.json"), b, 0600); e != nil {
		return "", nil, e
	}
	return clientOffloadNFT(rule, ip), rule, nil
}
func clientOffloadCleanup(r commandRunner) error {
	b, e := os.ReadFile(clientTestPath(".offload.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var saved clientOffloadRule
	if e = json.Unmarshal(b, &saved); e != nil {
		return e
	}
	out, e := r.Run("nft", "-a", "list", "chain", "inet", "fw4", "forward")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "jump "+clientOffloadName+" ") || !strings.Contains(line, `comment "purewrt_client_test"`) {
			continue
		}
		_, h, ok := strings.Cut(strings.TrimSpace(line), " # handle ")
		if !ok {
			return fmt.Errorf("cannot restore flow-offload rule")
		}
		if _, e = strconv.ParseUint(h, 10, 64); e != nil {
			return e
		}
		// One nft argument preserves the original expressions and quoted comments.
		if _, e = r.Run("nft", "replace rule inet fw4 forward handle "+h+" "+saved.Rule); e != nil {
			return fmt.Errorf("restore flow offloading: %w", e)
		}
	}
	_, _ = r.Run("nft", "flush", "chain", "inet", "fw4", clientOffloadName)
	_, _ = r.Run("nft", "delete", "chain", "inet", "fw4", clientOffloadName)
	_, _ = r.Run("nft", "delete", "set", "inet", "fw4", clientOffloadName)
	return os.Remove(clientTestPath(".offload.json"))
}
