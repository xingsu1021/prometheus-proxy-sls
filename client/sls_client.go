package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sls "github.com/aliyun/aliyun-log-go-sdk"
	"prometheus-remoteread-sls/config"
	"prometheus-remoteread-sls/logger"
	"prometheus-remoteread-sls/types"
)

// Client wraps the SLS client with Prometheus-specific functionality
type Client struct {
	client           *sls.Client
	config           *config.SLSConfig
	queryConcurrency int
	mu               sync.Mutex
	httpClient       *http.Client
}

// QueryOption functional option for query
type QueryOption func(*QueryOptions)

// QueryOptions holds query options
type QueryOptions struct {
	MaxResults   int
	Offset       int
	QueryTimeout time.Duration
}

// NewClient creates a new SLS client
func NewClient(cfg *config.SLSConfig) (*Client, error) {
	var creds *sls.Credentials
	if cfg.SecurityToken != "" {
		creds = &sls.Credentials{
			AccessKeyID:     cfg.AccessKeyID,
			AccessKeySecret: cfg.AccessKeySecret,
			SecurityToken:   cfg.SecurityToken,
		}
	} else {
		creds = &sls.Credentials{
			AccessKeyID:     cfg.AccessKeyID,
			AccessKeySecret: cfg.AccessKeySecret,
		}
	}

	client := &sls.Client{
		Endpoint:        cfg.Endpoint,
		AccessKeyID:     creds.AccessKeyID,
		AccessKeySecret: creds.AccessKeySecret,
		SecurityToken:   creds.SecurityToken,
	}

	// Create HTTP client for Prometheus API calls
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	return &Client{
		client:           client,
		config:           cfg,
		queryConcurrency: 10,
		httpClient:       httpClient,
	}, nil
}

// SetQueryConcurrency sets the concurrency for concurrent queries
func (c *Client) SetQueryConcurrency(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queryConcurrency = n
}

// GetSamples retrieves samples from SLS based on label matchers and time range
// First tries Prometheus API (for full PromQL support), falls back to SLS query
func (c *Client) GetSamples(matchers []types.LabelMatcher, startTime, endTime time.Time, opts types.QueryOptions) ([]types.SLSLogEntry, error) {
	// Build PromQL from matchers
	promQL := c.buildPromQLFromMatchers(matchers)

	logger.Debugf("[SLS_CLIENT] Trying Prometheus API with PromQL: %s", promQL)

	// Try Prometheus API first (supports full PromQL)
	entries, err := c.QueryPrometheus(promQL, startTime, endTime)
	if err != nil {
		logger.Debugf("[SLS_CLIENT] Prometheus API failed: %v, falling back to SLS query", err)
		// Fall back to SLS query
		query := c.buildQuery(matchers)
		result, err := c.executeQueryWithPagination(query, startTime, endTime, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %w", err)
		}
		return result.Logs, nil
	}

	return entries, nil
}

// buildPromQLFromMatchers builds a PromQL query from label matchers
func (c *Client) buildPromQLFromMatchers(matchers []types.LabelMatcher) string {
	if len(matchers) == 0 {
		return ".*" // Match all if no matchers
	}

	// Find __name__ matcher
	var metricName string
	var labelFilters []string

	for _, m := range matchers {
		if m.Name == "__name__" {
			switch m.Type {
			case types.LabelMatcherType_EQUAL:
				metricName = m.Value
			case types.LabelMatcherType_REGEX_MATCH:
				metricName = m.Value
			}
		} else {
			// Add label filter
			switch m.Type {
			case types.LabelMatcherType_EQUAL:
				labelFilters = append(labelFilters, fmt.Sprintf(`%s="%s"`, m.Name, m.Value))
			case types.LabelMatcherType_NOT_EQUAL:
				labelFilters = append(labelFilters, fmt.Sprintf(`%s!="%s"`, m.Name, m.Value))
			case types.LabelMatcherType_REGEX_MATCH:
				labelFilters = append(labelFilters, fmt.Sprintf(`%s=~"%s"`, m.Name, m.Value))
			case types.LabelMatcherType_REGEX_NO_MATCH:
				labelFilters = append(labelFilters, fmt.Sprintf(`%s!~"%s"`, m.Name, m.Value))
			}
		}
	}

	// Build PromQL
	var promQL string
	if metricName != "" {
		promQL = metricName
	} else {
		promQL = ".*"
	}

	if len(labelFilters) > 0 {
		promQL += "{" + strings.Join(labelFilters, ",") + "}"
	}

	return promQL
}

// buildQuery builds an SLS query string using SPL syntax
func (c *Client) buildQuery(matchers []types.LabelMatcher) string {
	// Use configured base query if available, otherwise default to "*"
	query := c.config.Query
	if query == "" {
		query = "*"
	}

	logger.Debugf("[SLS_CLIENT] Building query from base: %s", query)

	var conditions []string
	for _, m := range matchers {
		condition := c.matcherToCondition(m)
		if condition != "" {
			conditions = append(conditions, condition)
		}
	}

	if len(conditions) > 0 {
		// If query already contains "|", append to it
		if strings.Contains(query, "|") {
			query += " AND " + strings.Join(conditions, " AND ")
		} else {
			query += " | where " + strings.Join(conditions, " AND ")
		}
	}

	logger.Debugf("[SLS_CLIENT] Final query: %s", query)
	return query
}

// matcherToCondition converts a label matcher to an SLS WHERE condition
// Note: SLS (especially MetricStore) has limited function support.
// We only support simple equality/nequality for labels.
// For regex matches, we try to convert to simple contains or ignore if too complex.
func (c *Client) matcherToCondition(m types.LabelMatcher) string {
	switch m.Type {
	case types.LabelMatcherType_EQUAL:
		// For __name__, use exact match
		if m.Name == "__name__" {
			return fmt.Sprintf("__name__ = '%s'", escapeString(m.Value))
		}
		// For other labels, use = for simple equality
		return fmt.Sprintf("%s = '%s'", m.Name, escapeString(m.Value))
	case types.LabelMatcherType_NOT_EQUAL:
		if m.Name == "__name__" {
			return fmt.Sprintf("__name__ != '%s'", escapeString(m.Value))
		}
		return fmt.Sprintf("%s != '%s'", m.Name, escapeString(m.Value))
	case types.LabelMatcherType_REGEX_MATCH:
		// SLS doesn't support match() function for regex
		// For regex patterns, we try to convert simple patterns to contains
		// or skip if too complex
		value := m.Value
		// Handle simple patterns like "^value$" (exact match)
		if len(value) > 2 && strings.HasPrefix(value, "^") && strings.HasSuffix(value, "$") {
			exactValue := value[1 : len(value)-1]
			return fmt.Sprintf("%s = '%s'", m.Name, escapeString(exactValue))
		}
		// For complex regex, try contains (partial match)
		// Note: This is a approximation, not true regex
		logger.Debugf("[SLS_CLIENT] Warning: Converting regex '%s' to contains for label '%s'", m.Value, m.Name)
		return fmt.Sprintf("%s = '%s'", m.Name, escapeString(m.Value))
	case types.LabelMatcherType_REGEX_NO_MATCH:
		// Similar handling for negative regex
		value := m.Value
		if len(value) > 2 && strings.HasPrefix(value, "^") && strings.HasSuffix(value, "$") {
			exactValue := value[1 : len(value)-1]
			return fmt.Sprintf("%s != '%s'", m.Name, escapeString(exactValue))
		}
		return fmt.Sprintf("%s != '%s'", m.Name, escapeString(m.Value))
	default:
		return ""
	}
}

// escapeString escapes special characters in a string for SLS query
func escapeString(s string) string {
	result := ""
	for _, ch := range s {
		switch ch {
		case '\'':
			result += "\\'"
		case '\\':
			result += "\\\\"
		default:
			result += string(ch)
		}
	}
	return result
}

// executeQueryWithPagination executes a query with automatic pagination
func (c *Client) executeQueryWithPagination(query string, startTime, endTime time.Time, opts types.QueryOptions) (*types.SLSQueryResult, error) {
	var allLogs []types.SLSLogEntry
	var totalCount int64
	offset := 0
	maxResults := c.config.MaxResults
	hasMore := true

	if opts.MaxSamples > 0 && opts.MaxSamples < maxResults {
		maxResults = opts.MaxSamples
	}

	for hasMore && len(allLogs) < opts.MaxSamples {
		result, err := c.executeSingleQuery(query, startTime, endTime, offset, maxResults)
		if err != nil {
			return nil, fmt.Errorf("pagination query failed at offset %d: %w", offset, err)
		}

		allLogs = append(allLogs, result.Logs...)
		totalCount = result.TotalCount

		if len(result.Logs) < maxResults {
			hasMore = false
		} else if c.config.EnablePagination {
			offset += len(result.Logs)
			if opts.MaxSamples > 0 && len(allLogs) >= opts.MaxSamples {
				hasMore = false
			}
		} else {
			hasMore = false
		}
	}

	return &types.SLSQueryResult{
		Logs:       allLogs,
		TotalCount: totalCount,
		HasMore:    len(allLogs) < int(totalCount),
	}, nil
}

// executeSingleQuery executes a single SLS query
func (c *Client) executeSingleQuery(query string, startTime, endTime time.Time, offset, maxResults int) (*types.SLSQueryResult, error) {
	req := &sls.GetLogRequest{
		From:    int64(startTime.Unix()),
		To:      int64(endTime.Unix()),
		Query:   query,
		Lines:   int64(maxResults),
		Offset:  int64(offset),
		Reverse: false,
	}

	logger.Debugf("[SLS_CLIENT] Query: Project=%s, Logstore=%s, From=%d, To=%d, Query=%s, Offset=%d, Lines=%d",
		c.config.Project, c.config.Logstore, req.From, req.To, query, offset, maxResults)

	response, err := c.client.GetLogsV2(c.config.Project, c.config.Logstore, req)
	if err != nil {
		return nil, fmt.Errorf("SLS GetLogs request failed: %w", err)
	}

	logger.Debugf("[SLS_CLIENT] Response: Count=%d, Logs=%d", response.Count, len(response.Logs))

	var entries []types.SLSLogEntry
	for i, logMap := range response.Logs {
		logger.Debugf("[SLS_CLIENT] Raw log[%d]: %v", i, logMap)
		entry := c.parseLogEntry(logMap)
		if entry != nil {
			entries = append(entries, *entry)
			logger.Debugf("[SLS_CLIENT] Parsed entry[%d]: Metric=%s, Timestamp=%v, Value=%f",
				len(entries)-1, entry.MetricName, entry.Timestamp, entry.Value)
		} else {
			logger.Debugf("[SLS_CLIENT] Failed to parse log[%d]: entry is nil (probably missing __name__)", i)
		}
	}

	return &types.SLSQueryResult{
		Logs:       entries,
		TotalCount: response.Count,
		HasMore:    int64(len(entries)) < response.Count,
	}, nil
}

// parseLogEntry parses an SLS log entry into SLSLogEntry
func (c *Client) parseLogEntry(logMap map[string]string) *types.SLSLogEntry {
	entry := &types.SLSLogEntry{
		Labels: make(map[string]string),
	}

	// Parse timestamp - __time__ is in SECONDS (not milliseconds)
	if ts, ok := logMap["__time__"]; ok && ts != "" {
		if tsi, err := strconv.ParseInt(ts, 10, 64); err == nil {
			entry.Timestamp = time.Unix(tsi, 0)
		}
	}

	// Parse metric name
	if name, ok := logMap["__name__"]; ok && name != "" {
		entry.MetricName = name
	}

	// Parse value
	if val, ok := logMap["__value__"]; ok && val != "" {
		if v, err := strconv.ParseFloat(val, 64); err == nil {
			entry.Value = v
		}
	}

	// Parse __labels__ which uses format: key#$#value|key#$#value
	if labels, ok := logMap["__labels__"]; ok && labels != "" {
		parseSLSLabels(labels, entry.Labels)
	}

	// Add all other fields as labels (exclude internal fields)
	for k, v := range logMap {
		if !isInternalField(k) && v != "" {
			entry.Labels[k] = v
		}
	}

	// Skip entries without metric name
	if entry.MetricName == "" {
		return nil
	}

	return entry
}

// isInternalField checks if a field is an internal SLS field
func isInternalField(key string) bool {
	internalFields := []string{
		"__time__", "__name__", "__value__", "__labels__",
		"__time_nano__", "__topic__", "__source__",
	}
	for _, f := range internalFields {
		if key == f {
			return true
		}
	}
	return strings.HasPrefix(key, "__tag__:")
}

// parseSLSLabels parses SLS label format: key#$#value|key#$#value
func parseSLSLabels(labelStr string, labels map[string]string) {
	if labelStr == "" {
		return
	}

	// Try JSON format first
	var jsonLabels map[string]string
	if err := json.Unmarshal([]byte(labelStr), &jsonLabels); err == nil {
		for k, v := range jsonLabels {
			labels[k] = v
		}
		return
	}

	// Parse key#$#value|key#$#value format
	parts := strings.Split(labelStr, "|")
	for _, part := range parts {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "#$#", 2)
		if len(kv) == 2 {
			labels[kv[0]] = kv[1]
		}
	}
}

// Query executes a raw SLS query
func (c *Client) Query(query string, startTime, endTime time.Time, opts ...QueryOption) (*types.SLSQueryResult, error) {
	options := &QueryOptions{
		MaxResults:   c.config.MaxResults,
		QueryTimeout: 180 * time.Second,
	}

	for _, opt := range opts {
		opt(options)
	}

	return c.executeSingleQuery(query, startTime, endTime, 0, options.MaxResults)
}

// PrometheusQueryResult represents the response from Prometheus API
type PrometheusQueryResult struct {
	Status string         `json:"status"`
	Data   PrometheusData `json:"data"`
}

type PrometheusData struct {
	ResultType string          `json:"resultType"`
	Result     json.RawMessage `json:"result"` // Use RawMessage to handle both scalar and vector
}

// PrometheusResult for vector type
type PrometheusResult struct {
	Metric map[string]string `json:"metric"`
	// For range query: values (plural)
	Values interface{} `json:"values"`
	// For instant query: value (singular)
	Value interface{} `json:"value"`
}

// ScalarResult for scalar type
type ScalarResult struct {
	Timestamp interface{} `json:"timestamp"`
	Value     interface{} `json:"value"`
}

// usesGroupingByLabel checks if the PromQL query uses by() or without() grouping
// For example: "max by(pod) (...)" or "sum without(namespace) (...)"
// When grouping is used, Prometheus doesn't include __name__ in the result
func usesGroupingByLabel(promQL string) bool {
	lower := strings.ToLower(promQL)
	// Look for " by(" or " without(" patterns (with space prefix to avoid matching inside words)
	return strings.Contains(lower, " by(") || strings.Contains(lower, " without(")
}

// extractMetricNameFromQuery extracts the base metric name from a PromQL query
// For example: "max by(pod) (kube_pod_container_resource_requests{...})" -> "kube_pod_container_resource_requests"
// For example: "sum(rate(container_cpu_usage_seconds_total{...}[2m]))" -> "container_cpu_usage_seconds_total"
func extractMetricNameFromQuery(promQL string) string {
	trimmed := strings.TrimSpace(promQL)

	// Handle aggregation with by/without modifier: sum by(pod) (metric{...})
	// The pattern is: AGGREGATION by(LABEL) (METRIC{...})
	// We need to find the second ( first, which marks the start of the metric

	// List of aggregation functions that can have by/without modifiers
	aggPatterns := []string{
		"sum by(", "sum without(", "avg by(", "avg without(",
		"max by(", "max without(", "min by(", "min without(",
		"count by(", "count without(", "stddev by(", "stddev without(",
		"stdvar by(", "stdvar without(", "last by(", "last without(",
		"present by(", "bottomk by(", "topk by(",
	}

	// First, check for aggregation with by/without modifier
	for _, pattern := range aggPatterns {
		idx := strings.Index(strings.ToLower(trimmed), pattern)
		if idx >= 0 {
			logger.Debugf("[SLS_CLIENT] extractMetricName: matched pattern '%s' at idx %d", pattern, idx)
			// Found pattern like "max by(" - now find the opening parenthesis after the by clause
			// The structure is: max by(pod) (metric{...})
			// After "max by(" we have "pod) (metric{...})"
			afterPattern := trimmed[idx+len(pattern):] // After "max by(" - start of the by clause content
			logger.Debugf("[SLS_CLIENT] extractMetricName: afterPattern = '%s'", afterPattern)

			// Find the ) that closes the by clause
			closeByIdx := strings.Index(afterPattern, ")")
			if closeByIdx >= 0 {
				logger.Debugf("[SLS_CLIENT] extractMetricName: closeByIdx = %d", closeByIdx)
				// After the ) we should have " (metric{...})"
				afterCloseBy := afterPattern[closeByIdx+1:]
				logger.Debugf("[SLS_CLIENT] extractMetricName: afterCloseBy (before trim) = '%s'", afterCloseBy)

				// Skip any whitespace and find the opening ( for the metric
				afterCloseBy = strings.TrimLeft(afterCloseBy, " \t")
				logger.Debugf("[SLS_CLIENT] extractMetricName: afterCloseBy (after trim) = '%s'", afterCloseBy)

				if strings.HasPrefix(afterCloseBy, "(") {
					// Now we have "metric{...})"
					metricPart := afterCloseBy[1:] // Skip the leading (
					logger.Debugf("[SLS_CLIENT] extractMetricName: metricPart = '%s'", metricPart)

					// Extract metric name before { or )
					for i, c := range metricPart {
						if c == '{' || c == ')' {
							if i > 0 {
								name := strings.TrimSpace(metricPart[:i])
								if name != "" && !strings.HasPrefix(name, "\"") && !strings.HasPrefix(name, "'") {
									logger.Debugf("[SLS_CLIENT] Extracted metric name (by/without): %s", name)
									return name
								}
							}
						}
					}
					// If no { or ), return what's left
					name := strings.TrimSpace(metricPart)
					if name != "" {
						logger.Debugf("[SLS_CLIENT] Extracted metric name (by/without, no braces): %s", name)
						return name
					}
				} else {
					logger.Debugf("[SLS_CLIENT] extractMetricName: afterCloseBy doesn't start with '('")
				}
			} else {
				logger.Debugf("[SLS_CLIENT] extractMetricName: no closing ) found in by clause")
			}
		}
	}

	// Handle simple aggregation without by/without: sum(metric{...})
	simplePatterns := []string{
		"sum(", "avg(", "max(", "min(", "count(",
		"stddev(", "stdvar(", "last(",
		"rate(", "irate(", "increase(", "delta(", "idelta(", "deriv(",
		"avg_over_time(", "max_over_time(", "min_over_time(",
		"sum_over_time(", "count_over_time(", "last_over_time(",
		"present_over_time(", "hour(", "minute(", "day_of_month(",
		"day_of_week(", "days_in_month(", "month(", "year(",
	}

	for _, pattern := range simplePatterns {
		idx := strings.Index(strings.ToLower(trimmed), pattern)
		if idx >= 0 {
			// Get everything after the pattern
			after := trimmed[idx+len(pattern):]
			// Find the metric name before { or )
			for i, c := range after {
				if c == '{' || c == ')' {
					if i > 0 {
						name := strings.TrimSpace(after[:i])
						// Validate it looks like a metric name (not a label)
						if name != "" && !strings.HasPrefix(name, "\"") && !strings.HasPrefix(name, "'") {
							logger.Debugf("[SLS_CLIENT] Extracted metric name (simple): %s", name)
							return name
						}
					}
				}
			}
			// If no { or ), return what's left
			name := strings.TrimSpace(after)
			if name != "" {
				logger.Debugf("[SLS_CLIENT] Extracted metric name (simple, no braces): %s", name)
				return name
			}
		}
	}

	// If no pattern found, try to extract before {
	idx := strings.Index(trimmed, "{")
	if idx > 0 {
		name := strings.TrimSpace(trimmed[:idx])
		logger.Debugf("[SLS_CLIENT] Extracted metric name (fallback): %s", name)
		return name
	}

	logger.Debugf("[SLS_CLIENT] Could not extract metric name, using full query: %s", trimmed)
	return trimmed
}

// QueryPrometheus queries SLS MetricStore using Prometheus-compatible API
// This supports full PromQL including: sum, rate, etc.
func (c *Client) QueryPrometheus(promQL string, startTime, endTime time.Time) ([]types.SLSLogEntry, error) {
	// Build Prometheus API URL using endpoint from config
	// URL format: https://{project}.{sls-endpoint}/prometheus/{project}/{metricstore}/api/v1/query_range
	// Example: https://nas-1578441730305797-cn-shanghai.cn-shanghai.log.aliyuncs.com/prometheus/nas-1578441730305797-cn-shanghai/prometheus/api/v1/query_range

	// First build the base URL
	baseURL := fmt.Sprintf("https://%s.%s/prometheus/%s/%s/api/v1/query_range",
		c.config.Project, c.config.Endpoint, c.config.Project, c.config.Logstore)

	// Prepare POST form data
	formData := url.Values{}
	formData.Set("query", promQL)
	formData.Set("start", strconv.FormatInt(startTime.Unix(), 10))
	formData.Set("end", strconv.FormatInt(endTime.Unix(), 10))
	formData.Set("step", "15s")

	// Debug log - print full request details
	logger.Debugf("[SLS_CLIENT] ========================================")
	logger.Debugf("[SLS_CLIENT] Prometheus API Request:")
	logger.Debugf("[SLS_CLIENT]   Method: POST")
	logger.Debugf("[SLS_CLIENT]   URL: %s", baseURL)
	logger.Debugf("[SLS_CLIENT]   Auth: %s (masked)", c.config.AccessKeyID[:8]+"***")
	logger.Debugf("[SLS_CLIENT]   Query: %s", promQL)
	logger.Debugf("[SLS_CLIENT]   Time range: start=%v, end=%v, step=15s", startTime, endTime)
	logger.Debugf("[SLS_CLIENT] ========================================")

	// Prepare request
	req, err := http.NewRequest("POST", baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add authentication
	req.SetBasicAuth(c.config.AccessKeyID, c.config.AccessKeySecret)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	logger.Debugf("[SLS_CLIENT] Prometheus API response status: %d, body length: %d", resp.StatusCode, len(body))
	logger.Debugf("[SLS_CLIENT] Response body: %s", string(body))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Prometheus API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Extract metric name from query as fallback
	fallbackMetricName := extractMetricNameFromQuery(promQL)
	logger.Debugf("[SLS_CLIENT] Extracted fallback metric name: %s", fallbackMetricName)

	// Parse response
	var result PrometheusQueryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logger.Debugf("[SLS_CLIENT] Parsed result: Status=%s, ResultType=%s",
		result.Status, result.Data.ResultType)

	if result.Status != "success" {
		return nil, fmt.Errorf("Prometheus API returned error status: %s", result.Status)
	}

	// Initialize entries slice early to avoid "undefined" error
	var entries []types.SLSLogEntry

	// Check if query uses grouping (by/without) - if so, don't add __name__ when SLS doesn't return it
	usesGrouping := usesGroupingByLabel(promQL)
	if usesGrouping {
		logger.Debugf("[SLS_CLIENT] Query uses grouping (by/without) - will not add __name__ to results")
	}

	// Parse based on result type
	switch result.Data.ResultType {
	case "matrix":
		// Matrix: result is [{"metric": {...}, "values": [[ts, val], ...]}, ...]
		var matrixResults []PrometheusResult
		if err := json.Unmarshal(result.Data.Result, &matrixResults); err != nil {
			return nil, fmt.Errorf("failed to parse matrix result: %w", err)
		}

		if len(matrixResults) == 0 {
			logger.Debugf("[SLS_CLIENT] WARNING: No results in matrix response!")
			return entries, nil
		}

		logger.Debugf("[SLS_CLIENT] Processing %d result series", len(matrixResults))

		for idx, r := range matrixResults {
			logger.Debugf("[SLS_CLIENT] Series[%d]: Metric map size=%d", idx, len(r.Metric))

			// Get metric name - use __name__ from SLS response
			// If SLS doesn't return __name__ AND query uses by/without, leave metricName empty
			// This is correct Prometheus behavior - grouping queries don't include __name__
			metricName := r.Metric["__name__"]
			if metricName == "" && !usesGrouping {
				// Only use fallback if NOT using by/without grouping
				metricName = fallbackMetricName
			}
			logger.Debugf("[SLS_CLIENT] Series[%d]: __name__=%s", idx, metricName)

			// For range query, r.Values is []interface{} where each element is [timestamp, value]
			valueSlice, ok := r.Values.([]interface{})
			if !ok {
				logger.Debugf("[SLS_CLIENT] Series[%d]: WARNING - Values is not []interface{}, actual type: %T", idx, r.Values)
				continue
			}

			logger.Debugf("[SLS_CLIENT] Series[%d]: Values count=%d", idx, len(valueSlice))

			for _, v := range valueSlice {
				// v is [timestamp, value]
				valueArr, ok := v.([]interface{})
				if !ok || len(valueArr) != 2 {
					continue
				}

				// Parse timestamp (float to int64)
				tsFloat, ok := valueArr[0].(float64)
				if !ok {
					continue
				}
				timestamp := time.Unix(int64(tsFloat), 0)

				// Parse value
				var value float64
				if valueStr, ok := valueArr[1].(string); ok {
					if v, err := strconv.ParseFloat(valueStr, 64); err == nil {
						value = v
					}
				} else if valNum, ok := valueArr[1].(float64); ok {
					value = valNum
				} else {
					continue
				}

				// Create labels map (excluding __name__)
				labels := make(map[string]string)
				for k, v := range r.Metric {
					if k != "__name__" {
						labels[k] = v
					}
				}

				entries = append(entries, types.SLSLogEntry{
					MetricName: metricName,
					Timestamp:  timestamp,
					Value:      value,
					Labels:     labels,
				})

				logger.Debugf("[SLS_CLIENT] Parsed entry: metric=%s, timestamp=%v, value=%f, labels=%v",
					metricName, timestamp, value, labels)
			}
		}

	case "vector":
		// Vector: result is [{"metric": {...}, "value": [ts, val]}, ...]
		var vectorResults []PrometheusResult
		if err := json.Unmarshal(result.Data.Result, &vectorResults); err != nil {
			return nil, fmt.Errorf("failed to parse vector result: %w", err)
		}

		for _, r := range vectorResults {
			var valueData interface{}
			if r.Value != nil {
				valueData = r.Value
			}

			if valueData == nil {
				continue
			}

			valueArr, ok := valueData.([]interface{})
			if !ok || len(valueArr) != 2 {
				continue
			}

			tsFloat, _ := valueArr[0].(float64)
			timestamp := time.Unix(int64(tsFloat), 0)

			var value float64
			if valStr, ok := valueArr[1].(string); ok {
				if v, err := strconv.ParseFloat(valStr, 64); err == nil {
					value = v
				}
			} else if valNum, ok := valueArr[1].(float64); ok {
				value = valNum
			}

			metricName := r.Metric["__name__"]
			if metricName == "" {
				metricName = "unknown"
			}

			labels := make(map[string]string)
			for k, v := range r.Metric {
				if k != "__name__" {
					labels[k] = v
				}
			}

			entries = append(entries, types.SLSLogEntry{
				MetricName: metricName,
				Timestamp:  timestamp,
				Value:      value,
				Labels:     labels,
			})
		}

	default:
		logger.Debugf("[SLS_CLIENT] Unknown result type for range query: %s", result.Data.ResultType)
	}

	// Sort entries by timestamp (ascending order - required by Prometheus)
	if len(entries) > 1 {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Timestamp.Before(entries[j].Timestamp)
		})

		logger.Debugf("[SLS_CLIENT] After sorting - first entry: %v, last entry: %v",
			entries[0].Timestamp, entries[len(entries)-1].Timestamp)
	}

	logger.Debugf("[SLS_CLIENT] Prometheus API returned %d entries", len(entries))
	return entries, nil
}

// QueryPrometheusInstant queries SLS MetricStore using Prometheus instant query API
// This is for getting a single value at a specific point in time
func (c *Client) QueryPrometheusInstant(promQL string, queryTime time.Time) ([]types.SLSLogEntry, error) {
	// Build Prometheus API URL using endpoint from config
	// URL format: https://{project}.{sls-endpoint}/prometheus/{project}/{metricstore}/api/v1/query

	// First build the base URL
	baseURL := fmt.Sprintf("https://%s.%s/prometheus/%s/%s/api/v1/query",
		c.config.Project, c.config.Endpoint, c.config.Project, c.config.Logstore)

	// Prepare POST form data
	formData := url.Values{}
	formData.Set("query", promQL)
	formData.Set("time", strconv.FormatInt(queryTime.Unix(), 10))

	// Debug log - print full request details
	logger.Debugf("[SLS_CLIENT] ========================================")
	logger.Debugf("[SLS_CLIENT] Prometheus Instant Query Request:")
	logger.Debugf("[SLS_CLIENT]   Method: POST")
	logger.Debugf("[SLS_CLIENT]   URL: %s", baseURL)
	logger.Debugf("[SLS_CLIENT]   Query: %s", promQL)
	logger.Debugf("[SLS_CLIENT]   Time: %v", queryTime)
	logger.Debugf("[SLS_CLIENT] ========================================")

	// Prepare request
	req, err := http.NewRequest("POST", baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add authentication
	req.SetBasicAuth(c.config.AccessKeyID, c.config.AccessKeySecret)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	logger.Debugf("[SLS_CLIENT] Prometheus Instant Query response status: %d, body length: %d", resp.StatusCode, len(body))
	logger.Debugf("[SLS_CLIENT] Response body: %s", string(body))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Prometheus API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Extract metric name from query as fallback
	fallbackMetricName := extractMetricNameFromQuery(promQL)
	logger.Debugf("[SLS_CLIENT] Extracted fallback metric name: %s", fallbackMetricName)

	// Parse response - use the same struct but different field name
	var result PrometheusQueryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logger.Debugf("[SLS_CLIENT] Instant query parsed: Status=%s, ResultType=%s",
		result.Status, result.Data.ResultType)

	if result.Status != "success" {
		return nil, fmt.Errorf("Prometheus API returned error status: %s", result.Status)
	}

	// Convert Prometheus result to SLSLogEntry based on result type
	var entries []types.SLSLogEntry

	// Check if query uses grouping (by/without) - if so, don't add __name__ when SLS doesn't return it
	usesGrouping := usesGroupingByLabel(promQL)
	if usesGrouping {
		logger.Debugf("[SLS_CLIENT] Query uses grouping (by/without) - will not add __name__ to results")
	}

	switch result.Data.ResultType {
	case "scalar":
		// Scalar: result is [timestamp, value]
		var scalarData []interface{}
		if err := json.Unmarshal(result.Data.Result, &scalarData); err != nil {
			logger.Debugf("[SLS_CLIENT] Failed to parse scalar result: %v", err)
		} else if len(scalarData) >= 2 {
			// Create a synthetic entry for scalar
			var ts time.Time
			if tsFloat, ok := scalarData[0].(float64); ok {
				ts = time.Unix(int64(tsFloat), 0)
			}
			var value float64
			if valStr, ok := scalarData[1].(string); ok {
				if v, err := strconv.ParseFloat(valStr, 64); err == nil {
					value = v
				}
			} else if valNum, ok := scalarData[1].(float64); ok {
				value = valNum
			}
			// Use fallback metric name for scalar (unless grouping is used)
			scalarMetricName := fallbackMetricName
			if scalarMetricName == "" && !usesGroupingByLabel(promQL) {
				scalarMetricName = "scalar"
			}
			entries = append(entries, types.SLSLogEntry{
				MetricName: scalarMetricName,
				Timestamp:  ts,
				Value:      value,
				Labels:     map[string]string{},
			})
			logger.Debugf("[SLS_CLIENT] Parsed scalar: time=%v, value=%f", ts, value)
		}

	case "vector":
		// Vector: result is [{"metric": {...}, "value": [ts, val]}, ...]
		var vectorResults []PrometheusResult
		if err := json.Unmarshal(result.Data.Result, &vectorResults); err != nil {
			return nil, fmt.Errorf("failed to parse vector result: %w", err)
		}

		logger.Debugf("[SLS_CLIENT] Vector result count: %d", len(vectorResults))

		for idx, r := range vectorResults {
			// Check which field is present: "value" (instant query)
			var valueData interface{}
			if r.Value != nil {
				valueData = r.Value
			} else if r.Values != nil {
				valueData = r.Values
			}

			if valueData == nil {
				logger.Debugf("[SLS_CLIENT] Vector Series[%d]: WARNING - No value data", idx)
				continue
			}

			// For instant query, value is [timestamp, value] (single pair)
			valueArr, ok := valueData.([]interface{})
			if !ok || len(valueArr) != 2 {
				logger.Debugf("[SLS_CLIENT] Vector Series[%d]: WARNING - Value is not [timestamp, value], type: %T", idx, valueData)
				continue
			}

			// Parse timestamp (float to int64)
			tsFloat, ok := valueArr[0].(float64)
			if !ok {
				continue
			}
			timestamp := time.Unix(int64(tsFloat), 0)

			// Parse value
			var value float64
			if valueStr, ok := valueArr[1].(string); ok {
				if v, err := strconv.ParseFloat(valueStr, 64); err == nil {
					value = v
				}
			} else if valNum, ok := valueArr[1].(float64); ok {
				value = valNum
			} else {
				continue
			}

			// Get metric name from labels - MUST be __name__ or use fallback
			// SLS PromQL might not include __name__ in the metric map
			// If query uses by/without grouping, don't use fallback
			metricName := r.Metric["__name__"]
			if metricName == "" && !usesGrouping {
				// Only use fallback if NOT using by/without grouping
				metricName = fallbackMetricName
			}

			// Create labels map (excluding __name__)
			labels := make(map[string]string)
			for k, v := range r.Metric {
				if k != "__name__" {
					labels[k] = v
				}
			}

			entries = append(entries, types.SLSLogEntry{
				MetricName: metricName,
				Timestamp:  timestamp,
				Value:      value,
				Labels:     labels,
			})
		}

	default:
		logger.Debugf("[SLS_CLIENT] Unknown result type: %s", result.Data.ResultType)
	}

	logger.Debugf("[SLS_CLIENT] Prometheus Instant Query returned %d entries", len(entries))

	// Log first entry for debugging
	if len(entries) > 0 {
		first := entries[0]
		logger.Debugf("[SLS_CLIENT] First sample: name=%s, time=%v, value=%f, labels=%v",
			first.MetricName, first.Timestamp, first.Value, first.Labels)
	}

	return entries, nil
}

// GetClient returns the underlying SLS client
func (c *Client) GetClient() *sls.Client {
	return c.client
}

// Close closes the client connection
func (c *Client) Close() error {
	return nil
}

// WithMaxResults sets the maximum results for a query
func WithMaxResults(n int) QueryOption {
	return func(o *QueryOptions) {
		o.MaxResults = n
	}
}

// WithOffset sets the offset for a query
func WithOffset(n int) QueryOption {
	return func(o *QueryOptions) {
		o.Offset = n
	}
}

// WithQueryTimeout sets the timeout for a query
func WithQueryTimeout(d time.Duration) QueryOption {
	return func(o *QueryOptions) {
		o.QueryTimeout = d
	}
}
