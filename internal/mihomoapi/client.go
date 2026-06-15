package mihomoapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Client struct{ Base, Secret string }
type Proxy struct {
	Name    string           `json:"name"`
	Type    string           `json:"type"`
	Now     string           `json:"now"`
	Alive   bool             `json:"alive"`
	Delay   int              `json:"delay"`
	History []ProxyDelayItem `json:"history,omitempty"`
	All     []string         `json:"all,omitempty"`
}

type ProxyDelayItem struct {
	Time  string `json:"time"`
	Delay int    `json:"delay"`
}

// Shared clients (read vs write vs delay-test timeout class) —
// http.Client is safe for concurrent use, and reusing one keeps
// connection pooling on a single Transport instead of allocating a client
// per call. delayClient is wide because a group delay test probes every
// member node and mihomo replies only after the stragglers time out.
var (
	readClient  = &http.Client{Timeout: 3 * time.Second}
	writeClient = &http.Client{Timeout: 5 * time.Second}
	delayClient = &http.Client{Timeout: 15 * time.Second}
)

func (c Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, "http://"+c.Base+path, body)
	if err != nil {
		return nil, err
	}
	if c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	return req, nil
}

func (c Client) Get(path string, out any) error {
	req, err := c.newRequest("GET", path, nil)
	if err != nil {
		return err
	}
	resp, err := readClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mihomo GET %s failed: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c Client) Put(path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := c.newRequest("PUT", path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := writeClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mihomo PUT %s failed: %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c Client) Proxies() (map[string]Proxy, error) {
	var res struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := c.Get("/proxies", &res); err != nil {
		return nil, err
	}
	return res.Proxies, nil
}

func (c Client) ProxyProviders() (map[string]any, error) {
	var res struct {
		Providers map[string]any `json:"providers"`
	}
	if err := c.Get("/providers/proxies", &res); err != nil {
		return nil, err
	}
	return res.Providers, nil
}

func (c Client) SelectProxy(group, node string) error {
	return c.Put("/proxies/"+group, map[string]string{"name": node}, nil)
}

// GroupDelayTest fires mihomo's per-group latency test: every member node
// probes url and the reply maps node name → delay in ms (nodes that fail
// are absent). Uses delayClient — the call blocks until the slowest
// member answers or times out.
func (c Client) GroupDelayTest(group, testURL string, timeoutMs int) (map[string]int, error) {
	req, err := c.newRequest("GET", "/group/"+url.PathEscape(group)+"/delay", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("url", testURL)
	q.Set("timeout", strconv.Itoa(timeoutMs))
	req.URL.RawQuery = q.Encode()
	resp, err := delayClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mihomo GET group delay %s failed: %s", group, resp.Status)
	}
	out := map[string]int{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c Client) HealthCheckProvider(name string) error {
	return c.Get("/providers/proxies/"+name+"/healthcheck", &struct{}{})
}

// RuleProviderRefresh asks mihomo to reload one rule provider from its
// configured source URL/file in place — no restart, no full config
// reload. Mihomo exposes this as PUT /providers/rules/{name}; equivalent
// shape to the existing healthcheck endpoint.
func (c Client) RuleProviderRefresh(name string) error {
	return c.Put("/providers/rules/"+name, struct{}{}, nil)
}

// DeleteConnection terminates one active proxy connection by id. Used by
// the drain logic when switching nodes — keeps in-flight requests from
// being silently RST'd by the kernel when the group flips.
func (c Client) DeleteConnection(id string) error {
	req, err := c.newRequest("DELETE", "/connections/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := readClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		// 404 is fine — the connection already closed naturally between
		// our snapshot and the delete attempt.
		return fmt.Errorf("mihomo DELETE /connections/%s: %s", id, resp.Status)
	}
	return nil
}

// Connections returns the current snapshot — same shape SubscribeConnections
// streams. Used by the drain logic to enumerate which ids to delete.
func (c Client) Connections() (ConnectionSnapshot, error) {
	var s ConnectionSnapshot
	if err := c.Get("/connections", &s); err != nil {
		return s, err
	}
	return s, nil
}

// VersionInfo is the shape mihomo's GET /version returns: a tiny JSON
// object like {"meta": true, "version": "alpha-c59c99a0"}. Used by the
// LuCI Mihomo tab's status section to show what's currently running
// (which may differ from what's installed on disk if a binary upgrade
// hasn't been picked up via service restart yet).
type VersionInfo struct {
	Meta    bool   `json:"meta"`
	Version string `json:"version"`
}

// Version fetches the running mihomo version via its REST API. Errors
// out when the service isn't up — callers (status panel) should
// interpret that as "not running" and skip the version row.
func (c Client) Version() (VersionInfo, error) {
	var v VersionInfo
	if err := c.Get("/version", &v); err != nil {
		return v, err
	}
	return v, nil
}

// TrafficSample is one record from the /traffic websocket stream. Mihomo
// emits one per second carrying current up/down throughput in bytes/sec.
type TrafficSample struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// SubscribeTraffic opens a WebSocket to /traffic and emits one
// TrafficSample per server-side frame. The channel closes when ctx is
// cancelled or the server drops the connection. Errors that aren't simple
// connection closes are sent through errs (buffered length 1; later
// errors overwrite earlier ones — this is a fire-and-forget stream).
func (c Client) SubscribeTraffic(ctx context.Context) (<-chan TrafficSample, <-chan error, error) {
	conn, br, err := wsDial(ctx, c.Base, "/traffic", c.Secret)
	if err != nil {
		return nil, nil, err
	}
	out := make(chan TrafficSample, 8)
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errs)
		defer func() { _ = conn.Close() }()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			data, err := wsReadFrame(br)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					select {
					case errs <- err:
					default:
					}
				}
				return
			}
			var s TrafficSample
			if err := json.Unmarshal(data, &s); err != nil {
				continue // malformed frame — skip
			}
			select {
			case out <- s:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errs, nil
}

// ConnectionSnapshot is the parsed payload of one /connections frame.
// Mihomo sends a fresh full snapshot on every change — there's no diff
// protocol. Consumers wanting deltas should derive them by comparing
// consecutive snapshots.
type ConnectionSnapshot struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Connections   []Connection `json:"connections"`
}

// Connection is one entry inside a ConnectionSnapshot. The field set
// matches mihomo's exposition — extra fields are tolerated (encoding/json
// ignores unknown keys by default).
type Connection struct {
	ID       string   `json:"id"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Start    string   `json:"start"`
	Chains   []string `json:"chains,omitempty"`
	Rule     string   `json:"rule,omitempty"`
	Network  string   `json:"network,omitempty"`
}

// SubscribeConnections opens a WebSocket to /connections and emits one
// ConnectionSnapshot per frame. Same lifecycle semantics as
// SubscribeTraffic.
func (c Client) SubscribeConnections(ctx context.Context) (<-chan ConnectionSnapshot, <-chan error, error) {
	conn, br, err := wsDial(ctx, c.Base, "/connections", c.Secret)
	if err != nil {
		return nil, nil, err
	}
	out := make(chan ConnectionSnapshot, 4)
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errs)
		defer func() { _ = conn.Close() }()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			data, err := wsReadFrame(br)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					select {
					case errs <- err:
					default:
					}
				}
				return
			}
			var s ConnectionSnapshot
			if err := json.Unmarshal(data, &s); err != nil {
				continue
			}
			select {
			case out <- s:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errs, nil
}
