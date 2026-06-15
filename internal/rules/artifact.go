package rules

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const ArtifactVersion = 1

type NeutralRule struct {
	Type  string
	Value string
}

func RuleToNeutral(r Rule) (NeutralRule, bool) {
	switch r.Type {
	case Domain, DomainSuffix:
		return NeutralRule{Type: "domain", Value: r.Value}, true
	case IPCIDR:
		return NeutralRule{Type: "cidr4", Value: r.Value}, true
	case IPCIDR6:
		return NeutralRule{Type: "cidr6", Value: r.Value}, true
	case Native:
		return NeutralRule{Type: "native", Value: r.Value}, true
	default:
		return NeutralRule{}, false
	}
}

func WriteArtifact(w io.Writer, rules []NeutralRule) error {
	if _, err := fmt.Fprintf(w, "# purewrt-rule-artifact-v%d\n", ArtifactVersion); err != nil {
		return err
	}
	for _, r := range rules {
		if err := WriteArtifactRule(w, r); err != nil {
			return err
		}
	}
	return nil
}

func WriteArtifactRule(w io.Writer, r NeutralRule) error {
	if r.Type == "" || strings.TrimSpace(r.Value) == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "%s\t%s\n", r.Type, base64.StdEncoding.EncodeToString([]byte(r.Value)))
	return err
}

func ReadArtifact(rd io.Reader) ([]NeutralRule, error) {
	sc := bufio.NewScanner(rd)
	lineNo := 0
	var out []NeutralRule
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if lineNo == 1 && line != fmt.Sprintf("# purewrt-rule-artifact-v%d", ArtifactVersion) {
				return nil, fmt.Errorf("unsupported rule artifact version: %s", line)
			}
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid rule artifact line %d", lineNo)
		}
		data, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid rule artifact value at line %d: %w", lineNo, err)
		}
		out = append(out, NeutralRule{Type: parts[0], Value: string(data)})
	}
	return out, sc.Err()
}
