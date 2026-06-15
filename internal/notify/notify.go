// Package notify delivers best-effort push notifications for operational
// events (provider update failures, subscription expiry, mihomo
// auto-reverts). One POST per event, two wire formats:
//
//   - webhook (default): JSON body {"event","detail","host","ts"} — fits
//     generic webhook receivers, Slack-compatible relays, n8n, etc.
//   - ntfy: plain-text body with a Title header — drop-in for ntfy.sh or a
//     self-hosted ntfy instance; Telegram users can point a relay at it.
//
// Deliberately tiny and stdlib-only: failure to notify must never affect
// routing, so callers log-and-continue on error.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Event struct {
	Event  string    `json:"event"`
	Detail string    `json:"detail"`
	Host   string    `json:"host"`
	TS     time.Time `json:"ts"`
}

var client = &http.Client{Timeout: 10 * time.Second}

// Send posts one event to url using the given format ("ntfy" or anything
// else → webhook JSON). Empty url is the caller's responsibility to filter.
func Send(url, format string, ev Event) error {
	if ev.Host == "" {
		ev.Host, _ = os.Hostname()
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	var req *http.Request
	var err error
	if format == "ntfy" {
		req, err = http.NewRequest(http.MethodPost, url, bytes.NewBufferString(ev.Detail))
		if err != nil {
			return err
		}
		req.Header.Set("Title", "purewrt: "+ev.Event)
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		body, merr := json.Marshal(ev)
		if merr != nil {
			return merr
		}
		req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify POST %s: %s", ev.Event, resp.Status)
	}
	return nil
}
