package metrics

import (
	"strings"
	"testing"
)

func TestProductMetricsRegisterNoCounterFamilies(t *testing.T) {
	Default.ResetObservations()
	out := Default.Render()
	if strings.Contains(out, " counter\n") {
		t.Fatalf("product registry contains a counter family:\n%s", out)
	}
}
