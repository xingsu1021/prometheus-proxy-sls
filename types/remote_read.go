package types

import (
	"time"
)

// ReadRequest represents a Prometheus Remote Read request
type ReadRequest struct {
	// List of queries to execute
	Queries []Query `json:"queries"`
}

// Query represents a single query in a ReadRequest
type Query struct {
	// Start timestamp (inclusive) in milliseconds
	StartTimeMs int64 `json:"startTimeMs"`
	// End timestamp (inclusive) in milliseconds
	EndTimeMs int64 `json:"endTimeMs"`
	// List of label matchers
	Matchers []LabelMatcher `json:"matchers"`
	// Optional hints for the query execution
	Hints *QueryHints `json:"hints,omitempty"`
}

// LabelMatcher represents a label matcher
type LabelMatcher struct {
	Type  LabelMatcherType `json:"type"`
	Name  string           `json:"name"`
	Value string           `json:"value"`
}

// LabelMatcherType is the type of label matcher
type LabelMatcherType int32

const (
	LabelMatcherType_EQUAL          LabelMatcherType = 0
	LabelMatcherType_NOT_EQUAL      LabelMatcherType = 1
	LabelMatcherType_REGEX_MATCH    LabelMatcherType = 2
	LabelMatcherType_REGEX_NO_MATCH LabelMatcherType = 3
)

// QueryHints provides optional hints for query execution
type QueryHints struct {
	// Start timestamp (inclusive) in milliseconds
	StartMs int64 `json:"startMs"`
	// End timestamp (inclusive) in milliseconds
	EndMs int64 `json:"endMs"`
	// Target number of series per request
	TargetSeriesPerRequest int64 `json:"targetSeriesPerRequest,omitempty"`
	// Target number of samples per request
	TargetSamplesPerRequest int64 `json:"targetSamplesPerRequest,omitempty"`
}

// ReadResponse represents a Prometheus Remote Read response
type ReadResponse struct {
	// Results for each query
	Results []*QueryResult `json:"results"`
}

// QueryResult represents the result of a single query
type QueryResult struct {
	// Status of the query execution
	Status ResultStatus `json:"status"`
	// List of timeseries in the result
	Timeseries []TimeSeries `json:"timeseries,omitempty"`
	// Error message if status is error
	Error string `json:"error,omitempty"`
}

// ResultStatus represents the status of a query result
type ResultStatus int32

const (
	ResultStatus_SUCCESS ResultStatus = 0
	ResultStatus_ERROR   ResultStatus = 1
)

// TimeSeries represents a single time series
type TimeSeries struct {
	// Labels for the time series
	Labels []Label `json:"labels"`
	// Samples in the time series
	Samples []Sample `json:"samples"`
}

// Label represents a label
type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Sample represents a single sample
type Sample struct {
	// Timestamp in milliseconds
	TimestampMs int64 `json:"timestampMs"`
	// Sample value
	Value float64 `json:"value"`
}

// SLSLogEntry represents a log entry from SLS
type SLSLogEntry struct {
	Timestamp  time.Time         `json:"timestamp"`
	MetricName string            `json:"metric_name"`
	Labels     map[string]string `json:"labels"`
	Value      float64           `json:"value"`
}

// SLSQueryResult represents the result of an SLS query
type SLSQueryResult struct {
	Logs       []SLSLogEntry
	TotalCount int64
	HasMore    bool
}

// QueryOptions holds options for query execution
type QueryOptions struct {
	Timeout         time.Duration
	MaxSamples      int
	PartialResponse bool
}
