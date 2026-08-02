package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sync/atomic"
)

const persistentStateVersion = 1

// persistentState is the cross-process registry stored in RuntimeDir. CLI
// commands contribute deltas; gauges replace only samples explicitly set by
// that command. Keeping this separate from metrics.prom makes persistence
// lossless while the latter stays a plain scrape-ready snapshot.
type persistentState struct {
	Version    int                            `json:"version"`
	Counters   map[string]persistentCounter   `json:"counters,omitempty"`
	Gauges     map[string]persistentGauge     `json:"gauges,omitempty"`
	Histograms map[string]persistentHistogram `json:"histograms,omitempty"`
}

type persistentCounter struct {
	Help      string            `json:"help"`
	LabelKeys []string          `json:"label_keys,omitempty"`
	Samples   map[string]uint64 `json:"samples,omitempty"`
}

type persistentGauge struct {
	Help      string             `json:"help"`
	LabelKeys []string           `json:"label_keys,omitempty"`
	Samples   map[string]float64 `json:"samples,omitempty"`
}

type persistentHistogram struct {
	Help      string                          `json:"help"`
	LabelKeys []string                        `json:"label_keys,omitempty"`
	Buckets   []float64                       `json:"buckets"`
	Samples   map[string]persistentHistSample `json:"samples,omitempty"`
}

type persistentHistSample struct {
	Counts []uint64 `json:"counts"`
	Sum    float64  `json:"sum"`
	Count  uint64   `json:"count"`
}

func newPersistentState() persistentState {
	return persistentState{
		Version:    persistentStateVersion,
		Counters:   map[string]persistentCounter{},
		Gauges:     map[string]persistentGauge{},
		Histograms: map[string]persistentHistogram{},
	}
}

// MergePersistent adds the process-local observations in delta to a prior
// persistent JSON registry and returns the next JSON plus Prometheus text.
// Only currently registered metric definitions survive, so removing a metric
// from vars.go also removes it from the next snapshot.
func MergePersistent(priorJSON []byte, delta *Registry) ([]byte, string, error) {
	prior := newPersistentState()
	if len(priorJSON) > 0 {
		if err := json.Unmarshal(priorJSON, &prior); err != nil {
			return nil, "", fmt.Errorf("decode persistent metrics: %w", err)
		}
		if prior.Version != persistentStateVersion {
			return nil, "", fmt.Errorf("unsupported persistent metrics version %d", prior.Version)
		}
	}
	ensurePersistentMaps(&prior)
	if err := validatePersistentState(prior); err != nil {
		return nil, "", fmt.Errorf("validate persistent metrics: %w", err)
	}
	next := newPersistentState()

	delta.mu.RLock()
	defer delta.mu.RUnlock()

	for name, current := range delta.counters {
		stored := persistentCounter{Help: current.help, LabelKeys: append([]string(nil), current.labelKey...), Samples: map[string]uint64{}}
		if old, ok := prior.Counters[name]; ok && slices.Equal(old.LabelKeys, current.labelKey) {
			for key, value := range old.Samples {
				stored.Samples[key] = value
			}
		}
		current.mu.RLock()
		if current.reconcile {
			for key := range stored.Samples {
				if _, keep := current.retained[key]; !keep {
					delete(stored.Samples, key)
				}
			}
		}
		for key, value := range current.samples {
			stored.Samples[key] += atomic.LoadUint64(value)
		}
		current.mu.RUnlock()
		next.Counters[name] = stored
	}

	for name, current := range delta.gauges {
		stored := persistentGauge{Help: current.help, LabelKeys: append([]string(nil), current.labelKey...), Samples: map[string]float64{}}
		if old, ok := prior.Gauges[name]; ok && slices.Equal(old.LabelKeys, current.labelKey) {
			for key, value := range old.Samples {
				stored.Samples[key] = value
			}
		}
		current.mu.RLock()
		if current.reconcile {
			for key := range stored.Samples {
				if _, keep := current.retained[key]; !keep {
					delete(stored.Samples, key)
				}
			}
		}
		for key := range current.deleted {
			delete(stored.Samples, key)
		}
		for key, value := range current.samples {
			stored.Samples[key] = bits2float(atomic.LoadUint64(value))
		}
		current.mu.RUnlock()
		next.Gauges[name] = stored
	}

	for name, current := range delta.histograms {
		stored := persistentHistogram{
			Help:      current.help,
			LabelKeys: append([]string(nil), current.labelKey...),
			Buckets:   append([]float64(nil), current.buckets...),
			Samples:   map[string]persistentHistSample{},
		}
		if old, ok := prior.Histograms[name]; ok && slices.Equal(old.LabelKeys, current.labelKey) && slices.Equal(old.Buckets, current.buckets) {
			for key, sample := range old.Samples {
				stored.Samples[key] = persistentHistSample{Counts: append([]uint64(nil), sample.Counts...), Sum: sample.Sum, Count: sample.Count}
			}
		}
		current.mu.RLock()
		for key, sample := range current.samples {
			merged := stored.Samples[key]
			if len(merged.Counts) != len(current.buckets)+1 {
				merged.Counts = make([]uint64, len(current.buckets)+1)
			}
			for i := range merged.Counts {
				merged.Counts[i] += atomic.LoadUint64(&sample.counts[i])
			}
			merged.Sum += bits2float(atomic.LoadUint64(&sample.sumBits))
			merged.Count += atomic.LoadUint64(&sample.count)
			stored.Samples[key] = merged
		}
		current.mu.RUnlock()
		next.Histograms[name] = stored
	}

	if err := validatePersistentState(next); err != nil {
		return nil, "", fmt.Errorf("validate merged metrics: %w", err)
	}
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return append(encoded, '\n'), persistentRegistry(next).Render(), nil
}

// RenderPersistent renders a previously merged JSON registry. The API uses
// the atomic state file as its source of truth; metrics.prom remains a useful
// human-readable/debugging snapshot but is not part of scrape correctness.
func RenderPersistent(data []byte) (string, error) {
	state := newPersistentState()
	if err := json.Unmarshal(data, &state); err != nil {
		return "", fmt.Errorf("decode persistent metrics: %w", err)
	}
	if state.Version != persistentStateVersion {
		return "", fmt.Errorf("unsupported persistent metrics version %d", state.Version)
	}
	ensurePersistentMaps(&state)
	if err := validatePersistentState(state); err != nil {
		return "", fmt.Errorf("validate persistent metrics: %w", err)
	}
	return persistentRegistry(state).Render(), nil
}

func ensurePersistentMaps(s *persistentState) {
	if s.Counters == nil {
		s.Counters = map[string]persistentCounter{}
	}
	if s.Gauges == nil {
		s.Gauges = map[string]persistentGauge{}
	}
	if s.Histograms == nil {
		s.Histograms = map[string]persistentHistogram{}
	}
}

func validatePersistentState(s persistentState) error {
	for name, metric := range s.Counters {
		if err := validatePersistentSampleKeys(metric.Samples, len(metric.LabelKeys)); err != nil {
			return fmt.Errorf("counter %s: %w", name, err)
		}
	}
	for name, metric := range s.Gauges {
		if err := validatePersistentSampleKeys(metric.Samples, len(metric.LabelKeys)); err != nil {
			return fmt.Errorf("gauge %s: %w", name, err)
		}
	}
	for name, metric := range s.Histograms {
		if err := validateHistogramBuckets(metric.Buckets); err != nil {
			return fmt.Errorf("histogram %s: %w", name, err)
		}
		if err := validatePersistentSampleKeys(metric.Samples, len(metric.LabelKeys)); err != nil {
			return fmt.Errorf("histogram %s: %w", name, err)
		}
		for key, sample := range metric.Samples {
			if len(sample.Counts) != len(metric.Buckets)+1 {
				return fmt.Errorf("histogram %s sample %q: got %d bucket counts, want %d", name, key, len(sample.Counts), len(metric.Buckets)+1)
			}
			var count uint64
			for _, bucketCount := range sample.Counts {
				if math.MaxUint64-count < bucketCount {
					return fmt.Errorf("histogram %s sample %q: bucket count overflow", name, key)
				}
				count += bucketCount
			}
			if count != sample.Count {
				return fmt.Errorf("histogram %s sample %q: bucket total %d differs from count %d", name, key, count, sample.Count)
			}
		}
	}
	return nil
}

func validatePersistentSampleKeys[T any](samples map[string]T, labelCount int) error {
	for key := range samples {
		var values []string
		if err := json.Unmarshal([]byte(key), &values); err != nil || len(values) != labelCount {
			return fmt.Errorf("invalid sample label key %q", key)
		}
	}
	return nil
}

func validateHistogramBuckets(buckets []float64) error {
	for i, bucket := range buckets {
		if math.IsNaN(bucket) || math.IsInf(bucket, 0) {
			return fmt.Errorf("bucket %d is not finite", i)
		}
		if i > 0 && bucket <= buckets[i-1] {
			return fmt.Errorf("buckets are not strictly increasing")
		}
	}
	return nil
}

func persistentRegistry(s persistentState) *Registry {
	r := NewRegistry()
	for name, stored := range s.Counters {
		metric := r.NewCounter(name, stored.Help, stored.LabelKeys...)
		for key, value := range stored.Samples {
			v := value
			metric.samples[key] = &v
		}
	}
	for name, stored := range s.Gauges {
		metric := r.NewGauge(name, stored.Help, stored.LabelKeys...)
		for key, value := range stored.Samples {
			v := float64bits(value)
			metric.samples[key] = &v
		}
	}
	for name, stored := range s.Histograms {
		metric := r.NewHistogram(name, stored.Help, stored.Buckets, stored.LabelKeys...)
		for key, sample := range stored.Samples {
			hs := &histSample{counts: append([]uint64(nil), sample.Counts...), sumBits: float64bits(sample.Sum), count: sample.Count}
			metric.samples[key] = hs
		}
	}
	return r
}
