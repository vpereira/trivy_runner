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
	ProcessedOpsCounter               prometheus.Counter
	ProcessedErrorsCounter            prometheus.Counter
	CommandExecutionDurationHistogram *prometheus.HistogramVec // Optional
}

func NewMetrics(opsCounterOpts, errorsCounterOpts prometheus.CounterOpts, optionalMetrics ...*prometheus.HistogramVec) *Metrics {
	m := &Metrics{
		ProcessedOpsCounter:    prometheus.NewCounter(opsCounterOpts),
		ProcessedErrorsCounter: prometheus.NewCounter(errorsCounterOpts),
	}

	if len(optionalMetrics) > 0 && optionalMetrics[0] != nil {
		m.CommandExecutionDurationHistogram = optionalMetrics[0]
	}

	return m
}

// Register registers the Prometheus counters (and optional histogram) with the default registry.
func (m *Metrics) Register() {
	prometheus.MustRegister(m.ProcessedOpsCounter, m.ProcessedErrorsCounter)
	if m.CommandExecutionDurationHistogram != nil {
		prometheus.MustRegister(m.CommandExecutionDurationHistogram)
	}
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
