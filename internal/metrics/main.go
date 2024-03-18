// metrics/metrics.go

package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the Prometheus metrics counters.
type Metrics struct {
	ProcessedOpsCounter    prometheus.Counter
	ProcessedErrorsCounter prometheus.Counter
}

// NewMetrics initializes and returns a new Metrics instance with the provided counter options.
func NewMetrics(opsCounterOpts, errorsCounterOpts prometheus.CounterOpts) *Metrics {
	return &Metrics{
		ProcessedOpsCounter:    prometheus.NewCounter(opsCounterOpts),
		ProcessedErrorsCounter: prometheus.NewCounter(errorsCounterOpts),
	}
}

// Register registers the Prometheus counters with the default registry.
func (m *Metrics) Register() {
	prometheus.MustRegister(m.ProcessedOpsCounter)
	prometheus.MustRegister(m.ProcessedErrorsCounter)
}

func (m *Metrics) GetProcessedErrorsCounter() prometheus.Counter {
	return m.ProcessedErrorsCounter
}

// IncOpsProcessed increments the processed operations counter.
func (m *Metrics) IncOpsProcessed() {
	m.ProcessedOpsCounter.Inc()
}

// IncOpsProcessedErrors increments the processed operations errors counter.
func (m *Metrics) IncOpsProcessedErrors() {
	m.ProcessedErrorsCounter.Inc()
}

// StartMetricsServer starts an HTTP server on the given port to expose the registered Prometheus metrics.
func StartMetricsServer(port string) {
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Metrics server started on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
