package rules

import "strings"

func SectionForName(name string) string {
	n := strings.ToLower(name)
	pairs := map[string][]string{"media": {"youtube", "googlevideo", "netflix", "twitch", "spotify", "tiktok"}, "ai": {"openai", "chatgpt", "anthropic", "claude", "gemini", "perplexity"}}
	for sec, keys := range pairs {
		for _, k := range keys {
			if strings.Contains(n, k) {
				return sec
			}
		}
	}
	return "common"
}
