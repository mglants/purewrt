package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type portRange struct{ first, last int }

func parsePortRanges(value string) ([]portRange, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var out []portRange
	for _, token := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(token), "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid destination port range %q", token)
		}
		a, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || a < 1 || a > 65535 {
			return nil, fmt.Errorf("invalid destination port %q", token)
		}
		b := a
		if len(parts) == 2 {
			b, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
		if err != nil || b < a || b > 65535 {
			return nil, fmt.Errorf("invalid destination port range %q", token)
		}
		out = append(out, portRange{a, b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].first < out[j].first })
	merged := out[:0]
	for _, r := range out {
		if len(merged) > 0 && r.first <= merged[len(merged)-1].last+1 {
			if r.last > merged[len(merged)-1].last {
				merged[len(merged)-1].last = r.last
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged, nil
}

func formatPortRanges(ranges []portRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		part := strconv.Itoa(r.first)
		if r.last != r.first {
			part += "-" + strconv.Itoa(r.last)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// NormalizeDestinationPorts validates and merges overlapping or adjacent ranges.
func NormalizeDestinationPorts(value string) (string, error) {
	ranges, err := parsePortRanges(value)
	if err != nil {
		return "", err
	}
	return formatPortRanges(ranges), nil
}

func (s Section) ValidateMatch() error {
	if s.Action != "proxy" && s.Action != "zapret" {
		return nil
	}
	switch s.MatchProtocol {
	case "", "any", "tcp", "udp", "tcp_udp":
	default:
		return fmt.Errorf("unsupported match_protocol %q", s.MatchProtocol)
	}
	_, err := NormalizeDestinationPorts(s.DestinationPorts)
	return err
}

func (s Section) MatchesProtocol(protocol string) bool {
	if s.Action != "proxy" && s.Action != "zapret" {
		return true
	}
	switch s.MatchProtocol {
	case "", "any":
		return true
	case "tcp_udp":
		return protocol == "tcp" || protocol == "udp"
	default:
		return s.MatchProtocol == protocol
	}
}

// IntersectDestinationPorts treats an empty operand as unrestricted. The bool
// distinguishes an empty intersection from an unrestricted result.
func IntersectDestinationPorts(a, b string) (string, bool) {
	ar, err := parsePortRanges(a)
	if err != nil {
		return "", false
	}
	br, err := parsePortRanges(b)
	if err != nil {
		return "", false
	}
	if len(ar) == 0 {
		return formatPortRanges(br), true
	}
	if len(br) == 0 {
		return formatPortRanges(ar), true
	}
	var out []portRange
	for _, x := range ar {
		for _, y := range br {
			lo, hi := max(x.first, y.first), min(x.last, y.last)
			if lo <= hi {
				out = append(out, portRange{lo, hi})
			}
		}
	}
	return formatPortRanges(out), len(out) > 0
}
