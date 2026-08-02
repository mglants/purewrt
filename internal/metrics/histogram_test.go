package metrics

import (
	"strings"
	"sync"
	"testing"
)

func (r *testRegistry) newHistogram(name, help string, buckets []float64, keys ...string) *Histogram {
	return r.Registry.NewHistogram(name, help, buckets, keys...)
}

func TestHistogramRender(t *testing.T) {
	r := freshRegistry(t)
	h := r.newHistogram("purewrt_test_ms", "Test histogram", []float64{10, 100, 1000}, "group")
	h.Observe(5, "a")    // bucket le=10
	h.Observe(50, "a")   // bucket le=100
	h.Observe(50, "a")   // bucket le=100
	h.Observe(5000, "a") // +Inf
	out := r.Render()
	for _, want := range []string{
		"# TYPE purewrt_test_ms histogram",
		`purewrt_test_ms_bucket{group="a",le="10"} 1`,
		`purewrt_test_ms_bucket{group="a",le="100"} 3`,  // cumulative
		`purewrt_test_ms_bucket{group="a",le="1000"} 3`, // cumulative, no sample in this bucket
		`purewrt_test_ms_bucket{group="a",le="+Inf"} 4`,
		`purewrt_test_ms_sum{group="a"} 5105`,
		`purewrt_test_ms_count{group="a"} 4`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in render:\n%s", want, out)
		}
	}
}

func TestHistogramInfEqualsCount(t *testing.T) {
	r := freshRegistry(t)
	h := r.newHistogram("purewrt_test_ms", "X", []float64{10})
	for i := range 7 {
		h.Observe(float64(i * 5))
	}
	out := r.Render()
	// The +Inf cumulative bucket must equal _count — the invariant
	// histogram_quantile depends on.
	if !strings.Contains(out, `purewrt_test_ms_bucket{le="+Inf"} 7`) || !strings.Contains(out, "purewrt_test_ms_count 7") {
		t.Fatalf("+Inf != count:\n%s", out)
	}
}

func TestHistogramPreservesFractionalSeconds(t *testing.T) {
	r := freshRegistry(t)
	h := r.newHistogram("purewrt_test_seconds", "X", DurationBucketsSeconds, "stage")
	h.Observe(0.0004, "nft")
	out := r.Render()
	for _, want := range []string{
		`purewrt_test_seconds_bucket{stage="nft",le="0.001"} 1`,
		`purewrt_test_seconds_sum{stage="nft"} 0.0004`,
		`purewrt_test_seconds_count{stage="nft"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("fractional observation missing %q:\n%s", want, out)
		}
	}
}

func TestHistogramConcurrentObserve(t *testing.T) {
	r := freshRegistry(t)
	h := r.newHistogram("purewrt_test_seconds", "X", OperationDurationBucketsSeconds, "g")
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			for i := range 1000 {
				h.Observe(float64(i%7000), "x")
			}
		}(w)
	}
	wg.Wait()
	out := r.Render()
	if !strings.Contains(out, `purewrt_test_seconds_count{g="x"} 8000`) {
		t.Fatalf("lost observations:\n%s", out)
	}
}
