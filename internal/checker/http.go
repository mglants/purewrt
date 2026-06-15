package checker

import (
	"net/http"
	"time"
)

type HTTPResult struct {
	Status    string
	LatencyMS int64
	Error     string
}

func HTTPGet(url string) HTTPResult {
	st := time.Now()
	c := http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return HTTPResult{Error: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	return HTTPResult{Status: resp.Status, LatencyMS: time.Since(st).Milliseconds()}
}
