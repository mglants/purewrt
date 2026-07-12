package provider

import (
	"regexp"
	"strings"
)

// No dashes: generated names double as UCI section ids (libuci only allows
// [A-Za-z0-9_]), so a dash would force the legacy anonymous + `option name`
// serialization on every import.
var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9_]+`)
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
