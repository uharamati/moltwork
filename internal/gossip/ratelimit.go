package gossip

import (
	"sync"
	"time"
)

// RateLimiter tracks per-author entry rates (rules N5, N6).
type RateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateBucket
	limit    int           // max entries per window
	window   time.Duration // time window
}

type rateBucket struct {
	count    int
	windowStart time.Time
}

// NewRateLimiter creates a rate limiter with the given limit per window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		counters: make(map[string]*rateBucket),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if an author is within rate limits.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(authorID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, ok := rl.counters[authorID]
	if !ok || now.Sub(bucket.windowStart) > rl.window {
		rl.counters[authorID] = &rateBucket{count: 1, windowStart: now}
		return true
	}

	bucket.count++
	return bucket.count <= rl.limit
}

// Remaining returns how many entries the author can still send in the current window.
func (rl *RateLimiter) Remaining(authorID string) int {
	used := rl.Count(authorID)
	remaining := rl.limit - used
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Count returns the current count for an author in the current window.
func (rl *RateLimiter) Count(authorID string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, ok := rl.counters[authorID]
	if !ok {
		return 0
	}
	if time.Since(bucket.windowStart) > rl.window {
		return 0
	}
	return bucket.count
}
