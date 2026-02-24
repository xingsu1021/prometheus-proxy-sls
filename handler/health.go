package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"prometheus-remoteread-sls/client"
	"prometheus-remoteread-sls/config"
	"prometheus-remoteread-sls/logger"
	"prometheus-remoteread-sls/types"
)

// HealthHandler handles health check and monitoring requests
type HealthHandler struct {
	slsClient       *client.Client
	sampleQuery     string
	sampleTimeRange time.Duration
	endpoint        string
	project         string
	logstore        string
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(slsClient *client.Client, cfg *config.Config) *HealthHandler {
	sampleQuery := "*"
	if cfg.Health.SampleQuery != "" {
		sampleQuery = cfg.Health.SampleQuery
	}

	return &HealthHandler{
		slsClient:       slsClient,
		sampleQuery:     sampleQuery,
		sampleTimeRange: cfg.Health.SampleTimeRange,
		endpoint:        cfg.SLS.Endpoint,
		project:         cfg.SLS.Project,
		logstore:        cfg.SLS.Logstore,
	}
}

// ServeHTTP handles health check requests
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/health":
		h.handleHealthCheck(w, r)
	case "/health/live":
		h.handleLiveness(w, r)
	case "/health/ready":
		h.handleReadiness(w, r)
	case "/health/latest":
		h.handleLatestSample(w, r)
	case "/health/check":
		h.handleSelfCheck(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// handleHealthCheck performs a full health check including SLS connectivity
func (h *HealthHandler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	response := types.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
		SLS: types.SLSHealth{
			Connected: false,
			Endpoint:  h.endpoint,
			Project:   h.project,
			Logstore:  h.logstore,
		},
	}

	startTime := time.Now()
	queryTime := time.Now()

	// Debug log
	logger.Debugf("[HEALTH] /health check - sample_query: %s, query_time: %v", h.sampleQuery, queryTime)

	// Test SLS connectivity using Prometheus instant query API
	entries, err := h.slsClient.QueryPrometheusInstant(h.sampleQuery, queryTime)

	response.SLS.ResponseTime = fmt.Sprintf("%d", time.Since(startTime).Milliseconds())

	if err != nil {
		logger.Debugf("[HEALTH] /health check failed: %v", err)
		response.Status = "unhealthy"
		response.SLS.Connected = false
		response.SLS.Error = err.Error()
	} else {
		logger.Debugf("[HEALTH] /health check success - total %d entries", len(entries))
		if len(entries) > 0 {
			first := entries[0]
			logger.Debugf("[HEALTH] First sample: name=%s, time=%v, value=%f", first.MetricName, first.Timestamp, first.Value)
		}
		response.SLS.Connected = true
		response.SLS.TotalCount = len(entries)
		response.Status = "healthy"
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleLiveness returns just the liveness status
func (h *HealthHandler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleReadiness checks if the service is ready to accept traffic
func (h *HealthHandler) handleReadiness(w http.ResponseWriter, r *http.Request) {
	queryTime := time.Now()
	logger.Debugf("[HEALTH] /health/ready check - sample_query: %s, query_time: %v", h.sampleQuery, queryTime)

	// Quick SLS connectivity check using Prometheus instant query API
	entries, err := h.slsClient.QueryPrometheusInstant(h.sampleQuery, queryTime)

	if err != nil {
		logger.Debugf("[HEALTH] /health/ready check failed: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready"))
		return
	}

	logger.Debugf("[HEALTH] /health/ready check success - total %d entries", len(entries))
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready"))
}

// handleLatestSample returns the latest sample from SLS
func (h *HealthHandler) handleLatestSample(w http.ResponseWriter, r *http.Request) {
	response := types.LatestSampleResponse{
		Status:    "success",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	queryTime := time.Now()
	logger.Debugf("[HEALTH] /health/latest check - sample_query: %s, query_time: %v", h.sampleQuery, queryTime)

	// Query using Prometheus instant query API
	entries, err := h.slsClient.QueryPrometheusInstant(h.sampleQuery, queryTime)

	if err != nil {
		logger.Debugf("[HEALTH] /health/latest query failed: %v", err)
		response.Status = "error"
		response.Message = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	logger.Debugf("[HEALTH] /health/latest returned %d entries", len(entries))

	if len(entries) == 0 {
		response.Status = "no_data"
		response.Message = "No samples found"
		response.TotalCount = 0
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set total count
	response.TotalCount = len(entries)

	// Get the first entry
	first := entries[0]
	response.Sample = &types.SLSLogEntry{
		MetricName: first.MetricName,
		Timestamp:  first.Timestamp,
		Value:      first.Value,
		Labels:     first.Labels,
	}

	logger.Debugf("[HEALTH] /health/latest first sample: name=%s, time=%v, value=%f",
		first.MetricName, first.Timestamp, first.Value)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleSelfCheck performs a self-check by querying using sample_query from config
func (h *HealthHandler) handleSelfCheck(w http.ResponseWriter, r *http.Request) {
	response := types.SelfCheckResponse{
		Status:    "success",
		Timestamp: time.Now().Format(time.RFC3339),
		Metric:    h.sampleQuery,
	}

	// Query parameters - get last 24 hours of data (wider range for debugging)
	timeRange := 24 * time.Hour

	logger.Debugf("[SELF_CHECK] Starting self-check for metric: %s", h.sampleQuery)
	logger.Debugf("[SELF_CHECK] Time range: last %v", timeRange)

	startTime := time.Now().Add(-timeRange)
	endTime := time.Now()

	logger.Debugf("[SELF_CHECK] Query time: start=%v, end=%v", startTime, endTime)

	// Query SLS using Prometheus API (supports PromQL)
	entries, err := h.slsClient.QueryPrometheus(h.sampleQuery, startTime, endTime)

	if err != nil {
		logger.Debugf("[SELF_CHECK] Query failed: %v", err)
		response.Status = "error"
		response.Message = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response.TotalSLSLogs = len(entries)
	logger.Debugf("[SELF_CHECK] Prometheus API returned %d entries", len(entries))

	// Analyze the data
	if len(entries) > 0 {
		// Count unique label combinations (instances)
		uniqueInstances := make(map[string]int)
		uniqueLabels := make(map[string]bool)
		var timestamps []int64
		var values []float64

		for i, sample := range entries {
			// Get instance label
			instance := sample.Labels["instance"]
			if instance == "" {
				instance = "unknown"
			}
			uniqueInstances[instance]++

			// Build label key for deduplication check
			labelKey := ""
			for k, v := range sample.Labels {
				labelKey += k + "=" + v + ","
			}
			uniqueLabels[labelKey] = true

			// Collect timestamps
			timestamps = append(timestamps, sample.Timestamp.Unix())

			// Collect values
			values = append(values, sample.Value)

			logger.Debugf("[SELF_CHECK] Log[%d]: instance=%s, timestamp=%v, value=%f",
				i, instance, sample.Timestamp, sample.Value)
		}

		response.UniqueInstances = len(uniqueInstances)
		response.UniqueLabelCombinations = len(uniqueLabels)
		response.Message = fmt.Sprintf("Prometheus API returned %d logs, %d unique instances, %d unique label combinations",
			len(entries), len(uniqueInstances), len(uniqueLabels))

		// Add timestamp range
		if len(timestamps) > 0 {
			response.OldestTimestamp = time.Unix(timestamps[len(timestamps)-1], 0).Format(time.RFC3339)
			response.NewestTimestamp = time.Unix(timestamps[0], 0).Format(time.RFC3339)
		}

		// Add sample values
		response.SampleValues = values

		logger.Debugf("[SELF_CHECK] Analysis: %d unique instances, %d unique label combinations",
			len(uniqueInstances), len(uniqueLabels))
	} else {
		response.Message = "No data found in SLS for node_os_info in the last 1 hour"
		logger.Debugf("[SELF_CHECK] No data found in SLS")
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
