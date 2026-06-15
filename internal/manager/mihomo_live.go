package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/purewrt/purewrt/internal/mihomoapi"
)

// mihomoClient builds a client against the configured external controller.
// Shared by every method here so the UCI lookup happens once per call site
// rather than threading the URL + secret pair through caller args.
func (m Manager) mihomoClient() (mihomoapi.Client, error) {
	c, err := m.Load()
	if err != nil {
		return mihomoapi.Client{}, err
	}
	return mihomoapi.Client{Base: c.Settings.ExternalController, Secret: c.Settings.Secret}, nil
}

// contextWithTimeout5s wraps context.WithTimeout with a 5s budget so the
// import only needs `context` and `time` in this file.
func contextWithTimeout5s() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// MihomoTrafficSample opens a brief WebSocket subscription to /traffic,
// reads one sample, then closes. Used by the LuCI live-traffic panel
// which polls every 2s rather than holding an SSE connection through
// rpcd (rpcd is request/response, no streaming).
type MihomoTrafficSample struct {
	Up               int64 `json:"up"`
	Down             int64 `json:"down"`
	ConnectionsTotal int   `json:"connections_total,omitempty"`
}

func (m Manager) MihomoTrafficSample() (MihomoTrafficSample, error) {
	cli, err := m.mihomoClient()
	if err != nil {
		return MihomoTrafficSample{}, err
	}
	ctx, cancel := contextWithTimeout5s()
	defer cancel()
	ch, errs, err := cli.SubscribeTraffic(ctx)
	if err != nil {
		return MihomoTrafficSample{}, err
	}
	var sample mihomoapi.TrafficSample
	select {
	case s, ok := <-ch:
		if !ok {
			return MihomoTrafficSample{}, fmt.Errorf("mihomo /traffic closed before first sample")
		}
		sample = s
	case e := <-errs:
		if e != nil {
			return MihomoTrafficSample{}, e
		}
	case <-ctx.Done():
		return MihomoTrafficSample{}, fmt.Errorf("mihomo /traffic timeout: %w", ctx.Err())
	}
	// Drain remaining samples in a goroutine so the WS goroutine exits
	// cleanly. cancel() (deferred) hands it the ctx-cancel signal.
	go func() {
		for range ch {
		}
	}()
	out := MihomoTrafficSample{Up: sample.Up, Down: sample.Down}
	// Best-effort connections count via a separate cheap HTTP poll —
	// /connections snapshot is plain JSON, no WS dance needed.
	if snap, err := cli.Connections(); err == nil {
		out.ConnectionsTotal = len(snap.Connections)
	}
	return out, nil
}

// UpdateRuleProviderHotReload reloads one mihomo rule provider in place via
// PUT /providers/rules/{name}. Skips the whole purewrt apply pipeline —
// for cases where the user just wants the rule list refreshed without
// the cost of a full config rebuild.
func (m Manager) UpdateRuleProviderHotReload(name string) error {
	if name == "" {
		return fmt.Errorf("provider name is required")
	}
	cli, err := m.mihomoClient()
	if err != nil {
		return err
	}
	return cli.RuleProviderRefresh(name)
}
