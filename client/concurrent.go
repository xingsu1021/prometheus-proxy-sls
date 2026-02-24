package client

import (
	"context"
	"sync"
	"time"

	"prometheus-remoteread-sls/types"
)

// ConcurrentQueryResult holds the result of a concurrent query
type ConcurrentQueryResult struct {
	Logs []types.SLSLogEntry
	Err  error
}

// ConcurrentQuerier handles concurrent queries to SLS
type ConcurrentQuerier struct {
	client *Client
	sem    chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// NewConcurrentQuerier creates a new concurrent querier
func NewConcurrentQuerier(client *Client, concurrency int) *ConcurrentQuerier {
	return &ConcurrentQuerier{
		client: client,
		sem:    make(chan struct{}, concurrency),
	}
}

// QueryMultiple executes multiple queries concurrently
func (q *ConcurrentQuerier) QueryMultiple(ctx context.Context, queries []QueryTask) []ConcurrentQueryResult {
	results := make([]ConcurrentQueryResult, len(queries))

	for i, query := range queries {
		q.wg.Add(1)
		go func(index int, task QueryTask) {
			defer q.wg.Done()

			// Acquire semaphore
			select {
			case q.sem <- struct{}{}:
				defer func() { <-q.sem }()
			case <-ctx.Done():
				results[index] = ConcurrentQueryResult{
					Err: ctx.Err(),
				}
				return
			}

			// Parse time fields
			startTime, _ := task.StartTime.(time.Time)
			endTime, _ := task.EndTime.(time.Time)

			// Execute query
			logs, err := q.client.GetSamples(
				task.Matchers,
				startTime,
				endTime,
				task.Options,
			)

			q.mu.Lock()
			results[index] = ConcurrentQueryResult{
				Logs: logs,
				Err:  err,
			}
			q.mu.Unlock()
		}(i, query)
	}

	q.wg.Wait()
	return results
}

// QueryTask represents a single query task
type QueryTask struct {
	Matchers  []types.LabelMatcher
	StartTime interface{}
	EndTime   interface{}
	Options   types.QueryOptions
}

// ConcurrentGetSamples retrieves samples concurrently from multiple queries
func (c *Client) ConcurrentGetSamples(ctx context.Context, tasks []QueryTask, concurrency int) ([]types.SLSLogEntry, error) {
	querier := NewConcurrentQuerier(c, concurrency)
	results := querier.QueryMultiple(ctx, tasks)

	var allLogs []types.SLSLogEntry
	var firstErr error

	for _, result := range results {
		if result.Err != nil {
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
		allLogs = append(allLogs, result.Logs...)
	}

	return allLogs, firstErr
}
