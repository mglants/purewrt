package provider

import (
	"regexp"
	"strings"
)

var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
var safeUCINameRe = regexp.MustCompile(`[^a-z0-9]+`)

func SafeName(s string) string {
	if s == "" {
		return "main"
	}
	out := safeNameRe.ReplaceAllString(s, "_")
	if out == "" {
		return "main"
	}
	return out
}

func SafeUCIName(s string) string {
	out := strings.Trim(safeUCINameRe.ReplaceAllString(strings.ToLower(s), "_"), "_")
	if out == "" {
		return "main"
	}
	return out
}
