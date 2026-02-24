package handler

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/common/model"
	"prometheus-remoteread-sls/client"
	"prometheus-remoteread-sls/config"
	"prometheus-remoteread-sls/logger"
	"prometheus-remoteread-sls/prompb"
	"prometheus-remoteread-sls/types"
)

// RemoteReadHandler handles Prometheus Remote Read requests
type RemoteReadHandler struct {
	slsClient *client.Client
	config    *config.Config
}

// NewRemoteReadHandler creates a new Remote Read handler
func NewRemoteReadHandler(slsClient *client.Client, cfg *config.Config) *RemoteReadHandler {
	return &RemoteReadHandler{
		slsClient: slsClient,
		config:    cfg,
	}
}

// ServeHTTP implements http.Handler
func (h *RemoteReadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Log at the very beginning to confirm handler is invoked
	logger.Debugf("[REMOTE_READ] ===> Handler invoked: Method=%s, Path=%s, RemoteAddr=%s",
		r.Method, r.URL.Path, r.RemoteAddr)

	// Only handle Remote Read API
	// Use prefix match to handle query parameters
	if !strings.HasPrefix(r.URL.Path, "/api/v1/read") && r.URL.Path != "/read" {
		logger.Debugf("[REMOTE_READ] Path not found: %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	// Handle GET request for health checks (common for load balancers)
	if r.Method == http.MethodGet {
		logger.Debugf("[REMOTE_READ] Health check request received")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","handler":"remote_read"}`))
		return
	}

	if r.Method != http.MethodPost {
		logger.Debugf("[REMOTE_READ] Method not allowed: %s", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Debugf("[REMOTE_READ] Failed to read request body: %v", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	logger.Debugf("[REMOTE_READ] Received: ContentType=%s, Length=%d, Encoding=%s",
		r.Header.Get("Content-Type"), len(body), r.Header.Get("Content-Encoding"))

	// Decode protobuf request - Prometheus uses snappy compression
	var req prompb.ReadRequest

	// Always try snappy decompression first (Prometheus remote read always uses snappy)
	decompressed, err := snappy.Decode(nil, body)
	if err != nil {
		logger.Debugf("[REMOTE_READ] Snappy decompression failed: %v", err)
		// Fall back to raw unmarshal
		if err := proto.Unmarshal(body, &req); err != nil {
			logger.Debugf("[REMOTE_READ] Both raw and snappy unmarshal failed: %v", err)
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}
		logger.Debugf("[REMOTE_READ] Raw unmarshal succeeded")
	} else {
		logger.Debugf("[REMOTE_READ] Snappy decompressed size: %d", len(decompressed))
		if err := proto.Unmarshal(decompressed, &req); err != nil {
			logger.Debugf("[REMOTE_READ] Failed to unmarshal decompressed data: %v", err)
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}
		logger.Debugf("[REMOTE_READ] Snappy unmarshal succeeded")
	}

	logger.Debugf("[REMOTE_READ] Parsed: Queries=%d, AcceptedTypes=%v",
		len(req.Queries), req.AcceptedResponseTypes)

	// Always use SAMPLES response format (simpler, no XOR encoding needed)
	logger.Debugf("[REMOTE_READ] Using SAMPLES response format")
	h.handleSamplesResponse(w, r, &req)
}

// acceptsStreamedXORChunks checks if client accepts STREAMED_XOR_CHUNKS
func acceptsStreamedXORChunks(acceptedTypes []prompb.ReadRequest_ResponseType) bool {
	for _, t := range acceptedTypes {
		if t == prompb.ReadRequest_STREAMED_XOR_CHUNKS {
			return true
		}
	}
	return false
}

// handleSamplesResponse handles SAMPLES response type
func (h *RemoteReadHandler) handleSamplesResponse(w http.ResponseWriter, r *http.Request, req *prompb.ReadRequest) {
	ctx, cancel := context.WithTimeout(r.Context(), h.config.RemoteRead.QueryTimeout)
	defer cancel()

	// Log the incoming request details
	for i, query := range req.Queries {
		logger.Debugf("[REMOTE_READ] Query[%d]: StartTimestampMs=%d, EndTimestampMs=%d, MatchersCount=%d",
			i, query.StartTimestampMs, query.EndTimestampMs, len(query.Matchers))
		start := time.UnixMilli(query.StartTimestampMs)
		end := time.UnixMilli(query.EndTimestampMs)
		logger.Debugf("[REMOTE_READ] Query[%d] Time range: %v to %v (duration: %v)",
			i, start, end, end.Sub(start))
	}

	response := h.executeQueries(ctx, req)

	responseBody, err := proto.Marshal(response)
	if err != nil {
		logger.Debugf("[REMOTE_READ] Failed to marshal response: %v", err)
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	logger.Debugf("[REMOTE_READ] Response: Timeseries=%d, Size=%d", countTimeseries(response), len(responseBody))

	// Log timeseries details
	for i, result := range response.Results {
		if result != nil {
			logger.Debugf("[REMOTE_READ] Result[%d]: TimeseriesCount=%d", i, len(result.Timeseries))
			for j, ts := range result.Timeseries {
				logger.Debugf("[REMOTE_READ]   Timeseries[%d]: Labels=%v, SamplesCount=%d", j, ts.Labels, len(ts.Samples))
			}
		}
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Header().Set("Content-Encoding", "snappy")
	compressed := snappy.Encode(nil, responseBody)
	logger.Debugf("[REMOTE_READ] Compressed response size: %d", len(compressed))
	w.Write(compressed)
}

// handleStreamedResponse handles STREAMED_XOR_CHUNKS response type
func (h *RemoteReadHandler) handleStreamedResponse(w http.ResponseWriter, r *http.Request, req *prompb.ReadRequest) {
	ctx, cancel := context.WithTimeout(r.Context(), h.config.RemoteRead.QueryTimeout)
	defer cancel()
	_ = ctx

	// Set headers for streaming response
	w.Header().Set("Content-Type", "application/x-streamed-protobuf; proto=prometheus.ChunkedReadResponse")

	// Get samples for each query
	for i, query := range req.Queries {
		logger.Debugf("[REMOTE_READ] Query[%d]: Start=%d, End=%d, Matchers=%d",
			i, query.StartTimestampMs, query.EndTimestampMs, len(query.Matchers))

		startTime := time.UnixMilli(query.StartTimestampMs)
		endTime := time.UnixMilli(query.EndTimestampMs)

		matchers := convertMatchers(query.Matchers)

		samples, err := h.slsClient.GetSamples(matchers, startTime, endTime, types.QueryOptions{
			Timeout:         h.config.RemoteRead.QueryTimeout,
			MaxSamples:      h.config.RemoteRead.MaxSamples,
			PartialResponse: h.config.RemoteRead.PartialResponse,
		})

		if err != nil {
			logger.Debugf("[REMOTE_READ] SLS query failed: %v", err)
			continue
		}

		logger.Debugf("[REMOTE_READ] SLS returned %d samples", len(samples))

		// Create ChunkedReadResponse for this query
		chunkedResp := h.createChunkedResponse(i, samples)

		// Marshal the response
		data, err := proto.Marshal(chunkedResp)
		if err != nil {
			logger.Debugf("[REMOTE_READ] Failed to marshal chunked response: %v", err)
			continue
		}

		logger.Debugf("[REMOTE_READ] Streamed response: Series=%d, Chunks=%d, DataSize=%d",
			len(chunkedResp.ChunkedSeries), countChunks(chunkedResp), len(data))

		// Write in Prometheus streaming format:
		// 1. varint size prefix (uint64)
		// 2. big-endian uint32 CRC32 checksum (Castagnoli polynomial)
		// 3. protobuf data

		// Write varint size prefix
		var sizeBuf [binary.MaxVarintLen64]byte
		sizeN := binary.PutUvarint(sizeBuf[:], uint64(len(data)))
		if _, err := w.Write(sizeBuf[:sizeN]); err != nil {
			logger.Debugf("[REMOTE_READ] Failed to write size: %v", err)
			return
		}

		// Write CRC32 checksum (big-endian, Castagnoli polynomial)
		checksum := crc32Castagnoli(data)
		if _, err := w.Write(checksum); err != nil {
			logger.Debugf("[REMOTE_READ] Failed to write checksum: %v", err)
			return
		}

		// Write data
		if _, err := w.Write(data); err != nil {
			logger.Debugf("[REMOTE_READ] Failed to write data: %v", err)
			return
		}
	}
}

// crc32Castagnoli calculates CRC32 with Castagnoli polynomial
func crc32Castagnoli(data []byte) []byte {
	table := crc32.MakeTable(crc32.Castagnoli)
	crc := crc32.Checksum(data, table)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, crc)
	return buf
}

// createChunkedResponse creates a ChunkedReadResponse from samples
func (h *RemoteReadHandler) createChunkedResponse(queryIndex int, samples []types.SLSLogEntry) *prompb.ChunkedReadResponse {
	seriesMap := make(map[string][]types.SLSLogEntry)

	for _, sample := range samples {
		// Create label key from sample (includes metric name)
		labelKey := buildLabelKey(sample)
		seriesMap[labelKey] = append(seriesMap[labelKey], sample)
	}

	var chunkedSeries []*prompb.ChunkedSeries

	for _, seriesSamples := range seriesMap {
		var labels []prompb.Label
		if seriesSamples[0].MetricName != "" {
			labels = append(labels, prompb.Label{Name: "__name__", Value: seriesSamples[0].MetricName})
		}
		for k, v := range seriesSamples[0].Labels {
			if k != "__name__" {
				labels = append(labels, prompb.Label{Name: k, Value: v})
			}
		}

		chunks := h.createXORChunks(seriesSamples)

		chunkedSeries = append(chunkedSeries, &prompb.ChunkedSeries{
			Labels: labels,
			Chunks: chunks,
		})
	}

	return &prompb.ChunkedReadResponse{
		ChunkedSeries: chunkedSeries,
		QueryIndex:    int64(queryIndex),
	}
}

// createXORChunks creates XOR encoded chunks from samples
func (h *RemoteReadHandler) createXORChunks(samples []types.SLSLogEntry) []prompb.Chunk {
	if len(samples) == 0 {
		return nil
	}

	// Sort samples by timestamp
	for i := 0; i < len(samples)-1; i++ {
		for j := i + 1; j < len(samples); j++ {
			if samples[i].Timestamp.After(samples[j].Timestamp) {
				samples[i], samples[j] = samples[j], samples[i]
			}
		}
	}

	var values []byte
	for _, s := range samples {
		ts := s.Timestamp.UnixMilli()
		buf := make([]byte, 0, 16)
		buf = encodeVarint(buf, ts)
		buf = encodeFloat64(buf, s.Value)
		values = append(values, buf...)
	}

	return []prompb.Chunk{
		{
			MinTimeMs: samples[0].Timestamp.UnixMilli(),
			MaxTimeMs: samples[len(samples)-1].Timestamp.UnixMilli(),
			Type:      prompb.Chunk_XOR,
			Data:      values,
		},
	}
}

// encodeVarint encodes an int64 as varint
func encodeVarint(buf []byte, v int64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutVarint(tmp[:], v)
	return append(buf, tmp[:n]...)
}

// encodeFloat64 encodes a float64 as 8 bytes big-endian
func encodeFloat64(buf []byte, v float64) []byte {
	bits := uint64(0)
	*(*float64)(unsafe.Pointer(&bits)) = v
	return append(buf, byte(bits>>56), byte(bits>>48), byte(bits>>40), byte(bits>>32), byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
}

// executeQueries executes all queries in the request (for SAMPLES response)
func (h *RemoteReadHandler) executeQueries(ctx context.Context, req *prompb.ReadRequest) *prompb.ReadResponse {
	response := &prompb.ReadResponse{
		Results: make([]*prompb.QueryResult, len(req.Queries)),
	}

	var wg sync.WaitGroup
	resultsCh := make(chan int, len(req.Queries))

	for i, query := range req.Queries {
		wg.Add(1)
		go func(index int, q *prompb.Query) {
			defer wg.Done()
			defer func() { resultsCh <- index }()

			result := h.executeQuery(ctx, q)
			response.Results[index] = result
		}(i, query)
	}

	wg.Wait()
	close(resultsCh)

	return response
}

// executeQuery executes a single query
func (h *RemoteReadHandler) executeQuery(ctx context.Context, query *prompb.Query) *prompb.QueryResult {
	result := &prompb.QueryResult{}

	startTime := time.UnixMilli(query.StartTimestampMs)
	endTime := time.UnixMilli(query.EndTimestampMs)

	// Default query range: 15 minutes (only if range is too small)
	defaultQueryRange := 15 * time.Minute

	// If time range is too small or invalid, extend it to default range
	// This ensures we always have enough data for Prometheus queries
	queryRange := endTime.Sub(startTime)
	if queryRange < time.Minute {
		// Only extend if range is less than 1 minute (instant query or very small range)
		logger.Debugf("[REMOTE_READ] Query range too small (%v), extending to 15 minutes", queryRange)
		now := time.Now()
		startTime = now.Add(-defaultQueryRange)
		endTime = now
		logger.Debugf("[REMOTE_READ] Using extended range: %v to %v", startTime, endTime)
	}

	if startTime.After(endTime) {
		logger.Debugf("[REMOTE_READ] Invalid time range: start %v after end %v", startTime, endTime)
		return result
	}

	logger.Debugf("[REMOTE_READ] Query time range: %v to %v (duration: %v)", startTime, endTime, endTime.Sub(startTime))

	matchers := convertMatchers(query.Matchers)

	samples, err := h.slsClient.GetSamples(matchers, startTime, endTime, types.QueryOptions{
		Timeout:         h.config.RemoteRead.QueryTimeout,
		MaxSamples:      h.config.RemoteRead.MaxSamples,
		PartialResponse: h.config.RemoteRead.PartialResponse,
	})

	if err != nil {
		logger.Debugf("[REMOTE_READ] SLS query failed: %v", err)
		return result
	}

	logger.Debugf("[REMOTE_READ] SLS returned %d samples", len(samples))

	// Log each sample from SLS
	for i, s := range samples {
		logger.Debugf("[REMOTE_READ]   SLS_Sample[%d]: Timestamp=%v, MetricName=%s, Value=%f, Labels=%v",
			i, s.Timestamp, s.MetricName, s.Value, s.Labels)
	}

	timeseries := convertToTimeSeries(samples)
	logger.Debugf("[REMOTE_READ] Converted to %d timeseries from %d samples", len(timeseries), len(samples))

	// Log each timeseries
	for i, ts := range timeseries {
		logger.Debugf("[REMOTE_READ]   Timeseries[%d]: Labels=%d, Samples=%d", i, len(ts.Labels), len(ts.Samples))
		for j, s := range ts.Samples {
			logger.Debugf("[REMOTE_READ]     Sample[%d]: Timestamp=%d, Value=%f", j, s.Timestamp, s.Value)
		}
	}

	result.Timeseries = timeseries

	return result
}

// convertMatchers converts prompb matchers to client matchers
func convertMatchers(pbMatchers []*prompb.LabelMatcher) []types.LabelMatcher {
	var matchers []types.LabelMatcher
	for _, m := range pbMatchers {
		matchers = append(matchers, types.LabelMatcher{
			Type:  types.LabelMatcherType(m.Type),
			Name:  m.Name,
			Value: m.Value,
		})
	}
	return matchers
}

// convertToTimeSeries converts SLS samples to Prometheus format
// Samples with the same labels are merged into a single time series (standard Prometheus behavior)
func convertToTimeSeries(samples []types.SLSLogEntry) []*prompb.TimeSeries {
	seriesMap := make(map[string]*prompb.TimeSeries)

	logger.Debugf("[CONVERT] Starting conversion of %d samples", len(samples))

	for i, sample := range samples {
		// Create label key from sample (includes metric name)
		labelKey := buildLabelKey(sample)
		logger.Debugf("[CONVERT] Sample[%d]: Metric=%s, Timestamp=%v, Value=%f, LabelKey=%s",
			i, sample.MetricName, sample.Timestamp, sample.Value, labelKey)

		if _, exists := seriesMap[labelKey]; !exists {
			var labels []prompb.Label
			if sample.MetricName != "" {
				labels = append(labels, prompb.Label{Name: "__name__", Value: sample.MetricName})
			}
			for k, v := range sample.Labels {
				if k != "__name__" {
					labels = append(labels, prompb.Label{Name: k, Value: v})
				}
			}

			seriesMap[labelKey] = &prompb.TimeSeries{
				Labels:  labels,
				Samples: make([]prompb.Sample, 0),
			}
			logger.Debugf("[CONVERT] Created new timeseries for key=%s", labelKey)
		} else {
			logger.Debugf("[CONVERT] Appending to existing timeseries key=%s", labelKey)
		}

		seriesMap[labelKey].Samples = append(seriesMap[labelKey].Samples, prompb.Sample{
			Timestamp: sample.Timestamp.UnixMilli(),
			Value:     sample.Value,
		})
	}

	timeseries := make([]*prompb.TimeSeries, 0, len(seriesMap))
	for _, ts := range seriesMap {
		// Sort samples by timestamp (Prometheus requires ascending order)
		sortSamplesByTimestamp(ts.Samples)
		logger.Debugf("[CONVERT] Timeseries key=%s has %d samples after sorting", buildLabelKeyFromLabels(ts.Labels), len(ts.Samples))
		timeseries = append(timeseries, ts)
	}

	logger.Debugf("[CONVERT] Conversion complete: %d samples -> %d timeseries (merged by labels)", len(samples), len(timeseries))
	return timeseries
}

// sortSamplesByTimestamp sorts samples by timestamp in ascending order
func sortSamplesByTimestamp(samples []prompb.Sample) {
	if len(samples) < 2 {
		return
	}
	// Use bubble sort for simplicity (could use sort.Slice for larger datasets)
	for i := 0; i < len(samples)-1; i++ {
		for j := i + 1; j < len(samples); j++ {
			if samples[i].Timestamp > samples[j].Timestamp {
				samples[i], samples[j] = samples[j], samples[i]
			}
		}
	}
}

// buildLabelKey creates a unique key for a time series from map
// IMPORTANT: Must include __name__ to differentiate different metrics
func buildLabelKey(sample types.SLSLogEntry) string {
	// Start with metric name
	key := sample.MetricName

	// Add all labels in sorted order for consistency
	labelSet := make(model.LabelSet)
	for k, v := range sample.Labels {
		if k != "__name__" {
			labelSet[model.LabelName(k)] = model.LabelValue(v)
		}
	}

	// If there are labels, add them to the key
	if len(labelSet) > 0 {
		key += ":" + labelSet.String()
	}

	logger.Debugf("[CONVERT] buildLabelKey: metric=%s, labels=%v, key=%s", sample.MetricName, sample.Labels, key)
	return key
}

// buildLabelKeyFromLabels creates a unique key for a time series from prompb.Label
func buildLabelKeyFromLabels(labels []prompb.Label) string {
	labelSet := make(model.LabelSet)
	for _, l := range labels {
		if l.Name != "__name__" {
			labelSet[model.LabelName(l.Name)] = model.LabelValue(l.Value)
		}
	}
	return labelSet.String()
}

// countTimeseries counts total timeseries in response
func countTimeseries(resp *prompb.ReadResponse) int {
	total := 0
	for _, r := range resp.Results {
		total += len(r.Timeseries)
	}
	return total
}

// countChunks counts total chunks in ChunkedReadResponse
func countChunks(resp *prompb.ChunkedReadResponse) int {
	total := 0
	for _, cs := range resp.ChunkedSeries {
		total += len(cs.Chunks)
	}
	return total
}
