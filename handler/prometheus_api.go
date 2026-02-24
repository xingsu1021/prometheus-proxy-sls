package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"prometheus-remoteread-sls/client"
	"prometheus-remoteread-sls/config"
	"prometheus-remoteread-sls/logger"
	"prometheus-remoteread-sls/types"
)

// PrometheusAPIHandler handles Prometheus API requests (query, label values, etc.)
type PrometheusAPIHandler struct {
	slsClient *client.Client
	config    *config.Config
}

// NewPrometheusAPIHandler creates a new Prometheus API handler
func NewPrometheusAPIHandler(slsClient *client.Client, cfg *config.Config) *PrometheusAPIHandler {
	return &PrometheusAPIHandler{
		slsClient: slsClient,
		config:    cfg,
	}
}

// ServeHTTP handles Prometheus API requests
func (h *PrometheusAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/")

	logger.Debugf("[PROM_API] Request: Method=%s, Path=%s", r.Method, path)

	// Route based on path - NOTE: order matters! more specific routes first
	switch {
	case strings.HasPrefix(path, "api/v1/query_range"):
		// MUST check before "api/v1/query" since query_range is more specific
		h.handleQueryRange(w, r)
	case strings.HasPrefix(path, "api/v1/query"):
		h.handleQuery(w, r)
	case strings.HasPrefix(path, "api/v1/query_exemplars"):
		h.handleQueryExemplars(w, r)
	case strings.HasPrefix(path, "api/v1/label/") && strings.HasSuffix(path, "/values"):
		h.handleLabelValues(w, r)
	case strings.HasPrefix(path, "api/v1/labels"):
		h.handleLabels(w, r)
	case strings.HasPrefix(path, "api/v1/series"):
		h.handleSeries(w, r)
	case strings.HasPrefix(path, "api/v1/status/buildinfo"):
		h.handleBuildInfo(w, r)
	default:
		logger.Debugf("[PROM_API] Unknown endpoint: %s", path)
		h.writeError(w, "not_found", "endpoint not found")
	}
}

// handleQuery handles /api/v1/query (instant query)
func (h *PrometheusAPIHandler) handleQuery(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	queryTime := r.FormValue("time")

	logger.Debugf("[PROM_API] /api/v1/query: query=%s, time=%s", query, queryTime)

	var t time.Time
	if queryTime != "" {
		// Handle both integer and float timestamps
		ts, err := strconv.ParseFloat(queryTime, 64)
		if err != nil {
			logger.Debugf("[PROM_API] Invalid time parameter: %s", queryTime)
			h.writeError(w, "bad_data", "invalid time parameter")
			return
		}
		t = time.Unix(int64(ts), 0)
	} else {
		t = time.Now()
	}

	entries, err := h.slsClient.QueryPrometheusInstant(query, t)
	if err != nil {
		logger.Debugf("[PROM_API] Query failed: %v", err)
		h.writeError(w, "error", err.Error())
		return
	}

	// Convert to Prometheus format
	result := h.entriesToPrometheusVector(entries)
	h.writeSuccess(w, "vector", result)
}

// handleQueryRange handles /api/v1/query_range
func (h *PrometheusAPIHandler) handleQueryRange(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	startStr := r.FormValue("start")
	endStr := r.FormValue("end")
	step := r.FormValue("step")

	logger.Debugf("[PROM_API] /api/v1/query_range: query=%s, start=%s, end=%s, step=%s", query, startStr, endStr, step)

	// Handle both integer and float timestamps
	start, err := strconv.ParseFloat(startStr, 64)
	if err != nil {
		logger.Debugf("[PROM_API] Invalid start parameter: %s", startStr)
		h.writeError(w, "bad_data", "invalid start parameter")
		return
	}
	end, err := strconv.ParseFloat(endStr, 64)
	if err != nil {
		logger.Debugf("[PROM_API] Invalid end parameter: %s", endStr)
		h.writeError(w, "bad_data", "invalid end parameter")
		return
	}

	entries, err := h.slsClient.QueryPrometheus(query, time.Unix(int64(start), 0), time.Unix(int64(end), 0))
	if err != nil {
		logger.Debugf("[PROM_API] QueryRange failed: %v", err)
		h.writeError(w, "error", err.Error())
		return
	}

	// Convert to Prometheus format
	result := h.entriesToPrometheusMatrix(entries)
	h.writeSuccess(w, "matrix", result)
}

// handleLabelValues handles /api/v1/label/{label_name}/values
func (h *PrometheusAPIHandler) handleLabelValues(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	// Format: api/v1/label/{label_name}/values
	parts := strings.Split(path, "/")
	// parts: ["api", "v1", "label", "{label_name}", "values"]
	if len(parts) < 5 {
		logger.Debugf("[PROM_API] Invalid path: %s", path)
		h.writeError(w, "bad_data", "invalid path")
		return
	}
	labelName := parts[3] // index 3 = label_name

	logger.Debugf("[PROM_API] /api/v1/label/%s/values", labelName)

	// Get all unique values for this label
	match := r.FormValue("match[]")

	var entries []types.SLSLogEntry
	if match != "" {
		// Query with match filter
		now := time.Now()
		entries, _ = h.slsClient.QueryPrometheusInstant(match, now)
	} else {
		// Query a common metric to get label values
		// Use kube_node_info as it's a common metric in K8s
		entries, _ = h.slsClient.QueryPrometheusInstant("kube_node_info", time.Now())
	}

	// Extract unique label values
	uniqueValues := make(map[string]bool)
	for _, entry := range entries {
		if val, ok := entry.Labels[labelName]; ok {
			uniqueValues[val] = true
		}
		// Also check metric name
		if labelName == "__name__" {
			uniqueValues[entry.MetricName] = true
		}
	}

	// Convert to array
	var values []string
	for v := range uniqueValues {
		values = append(values, v)
	}

	logger.Debugf("[PROM_API] Label %s has %d unique values", labelName, len(values))

	// Write response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}{
		Status: "success",
		Data:   values,
	})
}

// handleLabels handles /api/v1/labels
func (h *PrometheusAPIHandler) handleLabels(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("[PROM_API] /api/v1/labels")

	// Query common K8s metrics to get all label names
	// Use multiple common metrics to get comprehensive label list
	commonMetrics := []string{
		"kube_node_info",
		"kube_pod_info",
		"kube_deployment_labels",
	}

	// Extract unique label names
	uniqueLabels := make(map[string]bool)

	for _, metric := range commonMetrics {
		entries, err := h.slsClient.QueryPrometheusInstant(metric, time.Now())
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Add all labels from the entry
			for k := range entry.Labels {
				uniqueLabels[k] = true
			}
			// Also add __name__
			uniqueLabels["__name__"] = true
		}
	}

	var labels []string
	for l := range uniqueLabels {
		labels = append(labels, l)
	}

	logger.Debugf("[PROM_API] Found %d unique labels", len(labels))

	// Write response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}{
		Status: "success",
		Data:   labels,
	})
}

// handleSeries handles /api/v1/series
func (h *PrometheusAPIHandler) handleSeries(w http.ResponseWriter, r *http.Request) {
	startStr := r.FormValue("start")
	endStr := r.FormValue("end")
	matches := r.Form["match[]"]

	logger.Debugf("[PROM_API] /api/v1/series: matches=%v, start=%s, end=%s", matches, startStr, endStr)

	start, _ := strconv.ParseInt(startStr, 10, 64)
	end, _ := strconv.ParseInt(endStr, 10, 64)
	if start == 0 {
		start = time.Now().Add(-5 * time.Minute).Unix()
	}
	if end == 0 {
		end = time.Now().Unix()
	}

	// Query each match
	var allSeries []map[string]string

	for _, match := range matches {
		entries, err := h.slsClient.QueryPrometheus(match, time.Unix(start, 0), time.Unix(end, 0))
		if err != nil {
			continue
		}

		for _, entry := range entries {
			series := make(map[string]string)
			series["__name__"] = entry.MetricName
			for k, v := range entry.Labels {
				series[k] = v
			}
			allSeries = append(allSeries, series)
		}
	}

	logger.Debugf("[PROM_API] Series returned %d unique series", len(allSeries))

	// Write response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Status string              `json:"status"`
		Data   []map[string]string `json:"data"`
	}{
		Status: "success",
		Data:   allSeries,
	})
}

// entriesToPrometheusVector converts entries to Prometheus instant query response format
func (h *PrometheusAPIHandler) entriesToPrometheusVector(entries []types.SLSLogEntry) []interface{} {
	var result []interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"metric": h.labelsToMap(entry.MetricName, entry.Labels),
			"value":  []interface{}{float64(entry.Timestamp.Unix()), strconv.FormatFloat(entry.Value, 'f', -1, 64)},
		})
	}
	return result
}

// entriesToPrometheusMatrix converts entries to Prometheus range query response format
func (h *PrometheusAPIHandler) entriesToPrometheusMatrix(entries []types.SLSLogEntry) []interface{} {
	// Group by labels
	seriesMap := make(map[string][]types.SLSLogEntry)
	for _, entry := range entries {
		key := fmt.Sprintf("%s:%v", entry.MetricName, entry.Labels)
		seriesMap[key] = append(seriesMap[key], entry)
	}

	var result []interface{}
	for _, series := range seriesMap {
		if len(series) == 0 {
			continue
		}

		var values []interface{}
		for _, entry := range series {
			values = append(values, []interface{}{
				float64(entry.Timestamp.Unix()),
				strconv.FormatFloat(entry.Value, 'f', -1, 64),
			})
		}

		result = append(result, map[string]interface{}{
			"metric": h.labelsToMap(series[0].MetricName, series[0].Labels),
			"values": values,
		})
	}
	return result
}

// labelsToMap converts metric name and labels to Prometheus format
func (h *PrometheusAPIHandler) labelsToMap(metricName string, labels map[string]string) map[string]string {
	result := make(map[string]string)
	if metricName != "" {
		result["__name__"] = metricName
	}
	for k, v := range labels {
		result[k] = v
	}
	return result
}

// writeSuccess writes a successful response
func (h *PrometheusAPIHandler) writeSuccess(w http.ResponseWriter, resultType string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"resultType": resultType,
			"result":     data,
		},
	})
}

// writeError writes an error response
func (h *PrometheusAPIHandler) writeError(w http.ResponseWriter, errorType, errorMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "error",
		"errorType": errorType,
		"error":     errorMsg,
	})
}

// handleBuildInfo handles /api/v1/status/buildinfo
func (h *PrometheusAPIHandler) handleBuildInfo(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("[PROM_API] /api/v1/status/buildinfo")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"application": "prometheus-remoteread-sls",
			"version":     "1.0.0",
			"revision":    "unknown",
			"branch":      "unknown",
			"buildUser":   "unknown",
			"buildDate":   "unknown",
			"goVersion":   "unknown",
		},
	})
}

// handleQueryExemplars handles /api/v1/query_exemplars
// Exemplars are used for tracing and are optional for Grafana
func (h *PrometheusAPIHandler) handleQueryExemplars(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	startStr := r.FormValue("start")
	endStr := r.FormValue("end")

	logger.Debugf("[PROM_API] /api/v1/query_exemplars: query=%s, start=%s, end=%s", query, startStr, endStr)

	// Return empty exemplars - SLS doesn't support exemplars natively
	// This is acceptable as most dashboards don't require exemplars
	h.writeSuccess(w, "exemplar", []interface{}{})
}
