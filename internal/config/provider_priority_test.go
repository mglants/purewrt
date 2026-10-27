package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyProviderPriorityIgnoredOnSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purewrt")
	input := "config section 'games'\n option priority '17'\nconfig rule_provider 'legacy'\n option priority '2'\n option section 'games'\n"
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sec, ok := c.SectionByName("games")
	if !ok || sec.Priority != 17 {
		t.Fatalf("section priority changed: %+v", sec)
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// There is exactly one section, so only its priority should remain.
	if strings.Count(string(data), "option priority") != 1 {
		t.Fatalf("provider priority survived save: %s", data)
	}
}
