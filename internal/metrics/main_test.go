package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_IncOpsProcessed(t *testing.T) {
	m := NewMetrics(prometheus.CounterOpts{Name: "processed_ops", Help: "The total number of processed operations."}, prometheus.CounterOpts{Name: "processed_errors", Help: "The total number of processed errors."})
	defer prometheus.Unregister(m.ProcessedOpsCounter)
	defer prometheus.Unregister(m.ProcessedErrorsCounter)

	m.Register()

	m.IncOpsProcessed()

	// Test if the OpsProcessed counter was incremented
	if want, got := 1.0, testutil.ToFloat64(m.ProcessedOpsCounter); want != got {
		t.Errorf("ProcessedOpsCounter = %f; want %f", got, want)
	}
}

func TestMetrics_IncOpsProcessedErrors(t *testing.T) {
	m := NewMetrics(prometheus.CounterOpts{Name: "processed_ops", Help: "The total number of processed operations."}, prometheus.CounterOpts{Name: "processed_errors", Help: "The total number of processed errors."})
	defer prometheus.Unregister(m.ProcessedOpsCounter)
	defer prometheus.Unregister(m.ProcessedErrorsCounter)

	m.Register()
	m.IncOpsProcessedErrors()

	// Test if the OpsProcessedErrors counter was incremented
	if want, got := 1.0, testutil.ToFloat64(m.ProcessedErrorsCounter); want != got {
		t.Errorf("ProcessedErrorsCounter = %f; want %f", got, want)
	}
}

func TestMetrics_Register(t *testing.T) {
	// Initialize a new Metrics instance
	m := NewMetrics(prometheus.CounterOpts{Name: "processed_ops", Help: "The total number of processed operations."}, prometheus.CounterOpts{Name: "processed_errors", Help: "The total number of processed errors."})

	// Attempt to register the metrics
	t.Run("Register Metrics", func(t *testing.T) {
		defer prometheus.Unregister(m.ProcessedOpsCounter)
		defer prometheus.Unregister(m.ProcessedErrorsCounter)
		// Define the expected metrics output
		expectedMetrics := `# HELP processed_ops The total number of processed operations.
							# TYPE processed_ops counter
							processed_ops 0
							`

		expectedErrorMetrics := `# HELP processed_errors The total number of processed errors.
								 # TYPE processed_errors counter
								 processed_errors 0
								`
		m.Register()

		if err := testutil.CollectAndCompare(m.ProcessedOpsCounter, strings.NewReader(expectedMetrics), "processed_ops"); err != nil {
			t.Errorf("ProcessedOpsCounter not registered or collected properly: %v", err)
		}

		if err := testutil.CollectAndCompare(m.ProcessedErrorsCounter, strings.NewReader(expectedErrorMetrics), "processed_errors"); err != nil {
			t.Errorf("ProcessedErrorsCounter not registered or collected properly: %v", err)
		}
	})
}
