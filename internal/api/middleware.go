package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"moltwork/internal/crypto"
	"moltwork/internal/logging"
)

// authRateLimiter tracks failed auth attempts per source to prevent brute-force.
type authRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	max      int
	window   time.Duration
}

func newAuthRateLimiter(max int, window time.Duration) *authRateLimiter {
	return &authRateLimiter{
		attempts: make(map[string][]time.Time),
		max:      max,
		window:   window,
	}
}

func (l *authRateLimiter) allow(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// Prune old entries
	recent := l.attempts[source][:0]
	for _, t := range l.attempts[source] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	l.attempts[source] = recent

	return len(recent) < l.max
}

func (l *authRateLimiter) record(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[source] = append(l.attempts[source], time.Now())
}

type contextKey string

const correlationIDKey contextKey = "correlation_id"

// authMiddleware validates the bearer token (rule N2, F4).
func authMiddleware(next http.Handler, token string, log *logging.Logger) http.Handler {
	limiter := newAuthRateLimiter(10, time.Minute)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := r.RemoteAddr

		// Check rate limit before processing
		if !limiter.allow(source) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		// Accept token from Authorization header or ?token= query param.
		// Query param enables browser-based access to the web UI.
		var providedToken string
		auth := r.Header.Get("Authorization")
		if auth != "" {
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				providedToken = parts[1]
			}
		}
		if providedToken == "" {
			providedToken = r.URL.Query().Get("token")
		}

		if providedToken == "" {
			limiter.record(source)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Constant-time comparison (rule C4)
		if !crypto.ConstantTimeEqual([]byte(providedToken), []byte(token)) {
			limiter.record(source)
			log.Warn("invalid bearer token attempt")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// correlationMiddleware generates a correlation ID per request (rule G2).
// The ID is set in both the request context and the response header.
func correlationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := hex.EncodeToString(crypto.RandomBytes(16))
		w.Header().Set("X-Correlation-ID", id)
		ctx := context.WithValue(r.Context(), correlationIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// securityHeaders adds required security headers (rules F2, F3, F6).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CSP (rule F2)
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")

		// No CORS — deny all cross-origin (rule F3)
		// Don't set Access-Control-Allow-Origin at all

		// X-Frame-Options DENY (rule F6)
		w.Header().Set("X-Frame-Options", "DENY")

		// Additional security headers (rule F6)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		next.ServeHTTP(w, r)
	})
}
