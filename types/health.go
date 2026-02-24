package types

// HealthCheckResponse represents the health check response
type HealthCheckResponse struct {
	Status    string    `json:"status"`
	SLS       SLSHealth `json:"sls"`
	Timestamp string    `json:"timestamp"`
}

// SLSHealth represents SLS connection health status
type SLSHealth struct {
	Connected    bool   `json:"connected"`
	Endpoint     string `json:"endpoint"`
	Project      string `json:"project"`
	Logstore     string `json:"logstore"`
	ResponseTime string `json:"response_time"`
	TotalCount   int    `json:"total_count"`
	Error        string `json:"error,omitempty"`
}

// LatestSampleResponse represents the latest sample data
type LatestSampleResponse struct {
	Status     string       `json:"status"`
	Sample     *SLSLogEntry `json:"sample,omitempty"`
	Timestamp  string       `json:"timestamp"`
	TotalCount int          `json:"total_count"`
	Message    string       `json:"message,omitempty"`
}

// SelfCheckResponse represents the self-check response for debugging
type SelfCheckResponse struct {
	Status                  string    `json:"status"`
	Timestamp               string    `json:"timestamp"`
	Metric                  string    `json:"metric"`
	TotalSLSLogs            int       `json:"total_sls_logs"`
	UniqueInstances         int       `json:"unique_instances"`
	UniqueLabelCombinations int       `json:"unique_label_combinations"`
	OldestTimestamp         string    `json:"oldest_timestamp,omitempty"`
	NewestTimestamp         string    `json:"newest_timestamp,omitempty"`
	SampleValues            []float64 `json:"sample_values,omitempty"`
	Message                 string    `json:"message"`
}
