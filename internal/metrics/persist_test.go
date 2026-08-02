package metrics

import (
	"fmt"
	"strings"
	"testing"
)

func TestMergePersistentAccumulatesAndPreservesDomains(t *testing.T) {
	first := NewRegistry()
	apply := first.NewCounter("purewrt_apply_total", "Apply", "result")
	lastCheck := first.NewGauge("purewrt_netcheck_last_run_timestamp_seconds", "Last check")
	duration := first.NewHistogram("purewrt_apply_duration_seconds", "Duration", []float64{0.1, 1})
	apply.WithLabelValues("ok")
	lastCheck.Set(1000)
	duration.Observe(0.05)

	state, _, err := MergePersistent(nil, first)
	if err != nil {
		t.Fatal(err)
	}
	first.ResetObservations()
	apply.WithLabelValues("ok")
	duration.Observe(0.2)
	state, out, err := MergePersistent(state, first)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`purewrt_apply_total{result="ok"} 2`,
		`purewrt_netcheck_last_run_timestamp_seconds 1000`,
		`purewrt_apply_duration_seconds_count 2`,
		`purewrt_apply_duration_seconds_sum 0.25`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q after merge:\n%s", want, out)
		}
	}
	_ = state
}

func TestMergePersistentCounterReconcile(t *testing.T) {
	r := NewRegistry()
	nodes := r.NewCounter("purewrt_netcheck_node_total", "Nodes", "node", "result")
	nodes.WithLabelValues("removed", "ok")
	nodes.WithLabelValues("kept", "ok")
	state, _, err := MergePersistent(nil, r)
	if err != nil {
		t.Fatal(err)
	}

	r.ResetObservations()
	nodes.KeepOnlyLabelValues([]string{"kept", "ok"}, []string{"kept", "fail"})
	nodes.WithLabelValues("kept", "ok")
	_, out, err := MergePersistent(state, r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `node="removed"`) {
		t.Fatalf("removed node survived counter reconciliation:\n%s", out)
	}
	if !strings.Contains(out, `purewrt_netcheck_node_total{node="kept",result="ok"} 2`) {
		t.Fatalf("retained node did not accumulate:\n%s", out)
	}
}

func TestRenderPersistentRejectsTruncatedHistogramState(t *testing.T) {
	state := fmt.Sprintf(`{
  "version": 1,
  "histograms": {
    "purewrt_broken": {
      "help": "Broken",
      "buckets": [10],
      "samples": { %q: {"counts": [], "sum": 0, "count": 0} }
    }
  }
}`, `[]`)
	if _, err := RenderPersistent([]byte(state)); err == nil {
		t.Fatal("truncated histogram state was accepted")
	}
}

func TestMergePersistentGaugeDelete(t *testing.T) {
	r := NewRegistry()
	g := r.NewGauge("purewrt_optional", "Optional")
	g.Set(42)
	state, _, err := MergePersistent(nil, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ResetObservations()
	g.Delete()
	_, out, err := MergePersistent(state, r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "purewrt_optional 42") {
		t.Fatalf("deleted gauge survived merge:\n%s", out)
	}
}

func TestMergePersistentGaugeReconcile(t *testing.T) {
	r := NewRegistry()
	status := r.NewGauge("purewrt_netcheck_node_status", "Latest node status", "node", "status")
	status.Set(1, "removed", "ok")
	status.Set(1, "kept", "ok")
	state, _, err := MergePersistent(nil, r)
	if err != nil {
		t.Fatal(err)
	}

	r.ResetObservations()
	status.Set(1, "kept", "throttled")
	status.KeepOnlyLabelValues([]string{"kept", "throttled"})
	_, out, err := MergePersistent(state, r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `node="removed"`) || strings.Contains(out, `status="ok"`) {
		t.Fatalf("stale latest-state labels survived gauge reconciliation:\n%s", out)
	}
	if !strings.Contains(out, `purewrt_netcheck_node_status{node="kept",status="throttled"} 1`) {
		t.Fatalf("current node status missing:\n%s", out)
	}
}

func TestMergePersistentPrunesReplacedMetricFamily(t *testing.T) {
	old := NewRegistry()
	old.NewHistogram("purewrt_generate_duration_ms", "Old", []float64{10}).Observe(5)
	state, _, err := MergePersistent(nil, old)
	if err != nil {
		t.Fatal(err)
	}

	current := NewRegistry()
	current.NewHistogram("purewrt_generate_duration_seconds", "New", DurationBucketsSeconds, "result").Observe(0.005, "generated")
	_, out, err := MergePersistent(state, current)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "purewrt_generate_duration_ms") {
		t.Fatalf("replaced millisecond family survived merge:\n%s", out)
	}
	if !strings.Contains(out, `purewrt_generate_duration_seconds_count{result="generated"} 1`) {
		t.Fatalf("replacement seconds family missing:\n%s", out)
	}
}
