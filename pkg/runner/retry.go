package runner

import (
	"context"
	"fmt"
	"strings"
	"time"
	
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
)

// RetryGetEntries fetches entries with retry logic
func RetryGetEntries(ctx context.Context, client *client.LogClient, start, end int64, maxRetries int) (*ct.GetEntriesResponse, error) {
	var lastErr error
	backoff := time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		entries, err := client.GetRawEntries(ctx, start, end)
		if err == nil {
			return entries, nil
		}
		
		lastErr = err
		errStr := strings.ToLower(err.Error())
		
		// Don't retry on context cancellation
		if ctx.Err() != nil {
			return nil, err
		}
		
		// Determine if we should retry
		if !shouldRetry(errStr) {
			return nil, err
		}
		
		// Wait before retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
			if backoff > 2*time.Minute {
				backoff = 2*time.Minute
			}
		}
	}
	
	return nil, fmt.Errorf("max retries exceeded: %v", lastErr)
}

func shouldRetry(errStr string) bool {
	retryableErrors := []string{
		"504", "502", "503", "429", "500",
		"timeout", "deadline exceeded",
		"connection refused", "connection reset",
	}
	
	for _, e := range retryableErrors {
		if strings.Contains(errStr, e) {
			return true
		}
	}
	
	// TrustAsia special case
	if strings.Contains(errStr, "400") && strings.Contains(errStr, "trustasia") {
		return true
	}
	
	return false
}
