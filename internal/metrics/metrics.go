// Package metrics is a tiny, stdlib-only Prometheus exposition layer used
// by `cmd/purewrt-api`'s /metrics endpoint. We intentionally don't pull in
// prometheus/client_golang — its dependency footprint (~600 KB on disk) is
// unwelcome on small OpenWrt targets, and the metric set PureWRT exposes
// fits inside a few hundred lines of code.
//
// Supported metric types: Counter (monotonic, can take labels) and Gauge
// (read/write). The exposition format follows the prometheus text spec
// (https://prometheus.io/docs/instrumenting/exposition_formats/) at the
// "good enough for prometheus and most scrapers" level — no histograms,
// no summaries, no native-histogram.
//
// All registry operations are concurrency-safe (RWMutex around the maps;
// atomic counters on each sample). Designed for read-mostly workloads —
// many scrapes, few writes per second from the apply path.
package metrics

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds Counters and Gauges keyed by metric name. One global
// `Default` registry is used by purewrt-api's /metrics handler; tests can
// build private registries via NewRegistry.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
}

// Default is the process-wide registry. Wired into the /metrics handler.
var Default = NewRegistry()

func NewRegistry() *Registry {
	return &Registry{
		counters:   map[string]*Counter{},
		gauges:     map[string]*Gauge{},
		histograms: map[string]*Histogram{},
	}
}

// Counter is a monotonically-increasing metric, optionally with labels.
type Counter struct {
	name     string
	help     string
	labelKey []string
	mu       sync.RWMutex
	samples  map[string]*uint64 // key = canonical label-value string
}

// NewCounter creates a Counter and registers it with the Default registry.
// labelKeys is the ordered list of label names; values are supplied at
// observation time via Counter.WithLabelValues.
func NewCounter(name, help string, labelKeys ...string) *Counter {
	c := &Counter{
		name:     name,
		help:     help,
		labelKey: append([]string(nil), labelKeys...),
		samples:  map[string]*uint64{},
	}
	Default.mu.Lock()
	Default.counters[name] = c
	Default.mu.Unlock()
	return c
}

// Inc bumps the unlabelled sample by 1. Use for label-free counters.
func (c *Counter) Inc() { c.AddLabels(1) }

// AddLabels increments the sample identified by the supplied label values.
// Must supply one value per label key declared at NewCounter time; any
// mismatch silently maps to the empty key (matches the prometheus
// client_golang behaviour for clearer error surfaces in the scrape).
func (c *Counter) AddLabels(delta uint64, labelValues ...string) {
	key := c.labelKey2sample(labelValues)
	c.mu.RLock()
	p, ok := c.samples[key]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		if p, ok = c.samples[key]; !ok {
			p = new(uint64)
			c.samples[key] = p
		}
		c.mu.Unlock()
	}
	atomic.AddUint64(p, delta)
}

// WithLabelValues is the conventional helper — same as AddLabels(1, …).
func (c *Counter) WithLabelValues(values ...string) { c.AddLabels(1, values...) }

func (c *Counter) labelKey2sample(values []string) string {
	if len(c.labelKey) == 0 {
		return ""
	}
	parts := make([]string, len(c.labelKey))
	for i, k := range c.labelKey {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		parts[i] = k + "=" + escape(v)
	}
	return strings.Join(parts, ",")
}

// Gauge is a read/write metric. No labels in this minimal implementation —
// adequate for the singletons PureWRT exposes (subscription_seconds_to_expiry,
// geoip_data_age_seconds, etc.).
type Gauge struct {
	name string
	help string
	bits uint64 // atomic-stored float64 bits
}

// NewGauge creates a Gauge and registers it on Default.
func NewGauge(name, help string) *Gauge {
	g := &Gauge{name: name, help: help}
	Default.mu.Lock()
	Default.gauges[name] = g
	Default.mu.Unlock()
	return g
}

// Set replaces the gauge value.
func (g *Gauge) Set(v float64) { atomic.StoreUint64(&g.bits, float64bits(v)) }

// Value reads the current sample.
func (g *Gauge) Value() float64 { return bits2float(atomic.LoadUint64(&g.bits)) }

// Histogram is a fixed-bucket latency histogram, optionally with labels.
// Buckets are upper bounds in ascending order; observations land in the
// first bucket whose bound is >= the value, with an implicit +Inf bucket.
// Exposition follows the prometheus text spec: cumulative `_bucket{le=}`
// rows plus `_sum` and `_count`.
type Histogram struct {
	name     string
	help     string
	labelKey []string
	buckets  []float64
	mu       sync.RWMutex
	samples  map[string]*histSample
}

type histSample struct {
	counts  []uint64 // one per bucket + final +Inf slot
	sumBits uint64   // atomic float64 bits, CAS-add
	count   uint64
}

// NewHistogram creates a Histogram and registers it on Default. buckets
// must be ascending; the +Inf bucket is implicit.
func NewHistogram(name, help string, buckets []float64, labelKeys ...string) *Histogram {
	h := &Histogram{
		name:     name,
		help:     help,
		labelKey: append([]string(nil), labelKeys...),
		buckets:  append([]float64(nil), buckets...),
		samples:  map[string]*histSample{},
	}
	Default.mu.Lock()
	Default.histograms[name] = h
	Default.mu.Unlock()
	return h
}

// Observe records one value against the sample identified by labelValues.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	key := h.labelKey2sample(labelValues)
	h.mu.RLock()
	s, ok := h.samples[key]
	h.mu.RUnlock()
	if !ok {
		h.mu.Lock()
		if s, ok = h.samples[key]; !ok {
			s = &histSample{counts: make([]uint64, len(h.buckets)+1)}
			h.samples[key] = s
		}
		h.mu.Unlock()
	}
	idx := len(h.buckets) // +Inf slot
	for i, ub := range h.buckets {
		if v <= ub {
			idx = i
			break
		}
	}
	atomic.AddUint64(&s.counts[idx], 1)
	atomic.AddUint64(&s.count, 1)
	for {
		old := atomic.LoadUint64(&s.sumBits)
		next := float64bits(bits2float(old) + v)
		if atomic.CompareAndSwapUint64(&s.sumBits, old, next) {
			break
		}
	}
}

func (h *Histogram) labelKey2sample(values []string) string {
	if len(h.labelKey) == 0 {
		return ""
	}
	parts := make([]string, len(h.labelKey))
	for i, k := range h.labelKey {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		parts[i] = k + "=" + escape(v)
	}
	return strings.Join(parts, ",")
}

// Render emits the Default registry contents in prometheus text format.
// Output is deterministic (metrics sorted by name; samples sorted by label
// key) so scrapers and goldenfile-style tests stay stable.
func (r *Registry) Render() string {
	r.mu.RLock()
	counters := make([]*Counter, 0, len(r.counters))
	for _, c := range r.counters {
		counters = append(counters, c)
	}
	gauges := make([]*Gauge, 0, len(r.gauges))
	for _, g := range r.gauges {
		gauges = append(gauges, g)
	}
	histograms := make([]*Histogram, 0, len(r.histograms))
	for _, h := range r.histograms {
		histograms = append(histograms, h)
	}
	r.mu.RUnlock()
	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })
	sort.Slice(histograms, func(i, j int) bool { return histograms[i].name < histograms[j].name })

	var b strings.Builder
	for _, c := range counters {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
		c.mu.RLock()
		keys := make([]string, 0, len(c.samples))
		for k := range c.samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := atomic.LoadUint64(c.samples[k])
			if k == "" {
				fmt.Fprintf(&b, "%s %d\n", c.name, v)
			} else {
				fmt.Fprintf(&b, "%s{%s} %d\n", c.name, formatLabels(k), v)
			}
		}
		c.mu.RUnlock()
	}
	for _, g := range gauges {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", g.name, g.help, g.name, g.name, g.Value())
	}
	for _, h := range histograms {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
		h.mu.RLock()
		keys := make([]string, 0, len(h.samples))
		for k := range h.samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := h.samples[k]
			labelPrefix := ""
			if k != "" {
				labelPrefix = formatLabels(k) + ","
			}
			cum := uint64(0)
			for i, ub := range h.buckets {
				cum += atomic.LoadUint64(&s.counts[i])
				fmt.Fprintf(&b, "%s_bucket{%sle=\"%g\"} %d\n", h.name, labelPrefix, ub, cum)
			}
			cum += atomic.LoadUint64(&s.counts[len(h.buckets)])
			fmt.Fprintf(&b, "%s_bucket{%sle=\"+Inf\"} %d\n", h.name, labelPrefix, cum)
			if k == "" {
				fmt.Fprintf(&b, "%s_sum %g\n%s_count %d\n", h.name, bits2float(atomic.LoadUint64(&s.sumBits)), h.name, atomic.LoadUint64(&s.count))
			} else {
				fmt.Fprintf(&b, "%s_sum{%s} %g\n%s_count{%s} %d\n", h.name, formatLabels(k), bits2float(atomic.LoadUint64(&s.sumBits)), h.name, formatLabels(k), atomic.LoadUint64(&s.count))
			}
		}
		h.mu.RUnlock()
	}
	return b.String()
}

// Handler returns an http.Handler that emits the Default registry's text
// exposition with the conventional content-type.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(Default.Render()))
	})
}

// ---- internals ----

func formatLabels(internalKey string) string {
	// internalKey is `k=v,k=v` already escaped; we just wrap each value in
	// quotes for the prometheus text format.
	parts := strings.Split(internalKey, ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			out[i] = p
			continue
		}
		out[i] = p[:eq] + `="` + p[eq+1:] + `"`
	}
	return strings.Join(out, ",")
}

func escape(s string) string {
	// Prometheus label values are arbitrary UTF-8 but must avoid newlines
	// and unescaped double-quotes. We aggressively escape both.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// float64bits/bits2float wrap math.Float64bits to keep Gauge.Set atomic
// without bringing unsafe into the public path.
func float64bits(v float64) uint64 { return math.Float64bits(v) }
func bits2float(b uint64) float64  { return math.Float64frombits(b) }
