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

	// Prune old entries for this source
	recent := l.attempts[source][:0]
	for _, t := range l.attempts[source] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(l.attempts, source) // Remove empty entries to prevent unbounded map growth
		return true
	}
	l.attempts[source] = recent

	// Cap total tracked sources to prevent memory exhaustion from distributed attacks
	if len(l.attempts) > 10000 {
		for k := range l.attempts {
			if k != source {
				delete(l.attempts, k)
				break
			}
		}
	}

	return len(recent) < l.max
}

func (l *authRateLimiter) record(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[source] = append(l.attempts[source], time.Now())
}

type contextKey string

const correlationIDKey contextKey = "correlation_id"

const sessionCookieName = "moltwork_session"

// authMiddleware validates the bearer token (rule N2, F4).
func authMiddleware(next http.Handler, token string, log *logging.Logger) http.Handler {
	limiter := newAuthRateLimiter(10, time.Minute)

	// Derive a session cookie value from the token so it's not the raw token
	// but still verifiable. HMAC(token, "session") would be ideal but for a
	// localhost-only server, a hex-encoded hash is sufficient.
	h := crypto.Hash([]byte(token))
	sessionValue := hex.EncodeToString(h[:])

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static assets don't need auth — they're just JS/CSS/fonts.
		// The HTML and API calls are what carry sensitive data.
		if strings.HasPrefix(r.URL.Path, "/_app/") {
			next.ServeHTTP(w, r)
			return
		}

		// Sync endpoints use PSK authentication, not bearer tokens.
		if strings.HasPrefix(r.URL.Path, "/api/sync/") {
			next.ServeHTTP(w, r)
			return
		}

		source := r.RemoteAddr

		// Check rate limit before processing
		if !limiter.allow(source) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		// Check auth sources in order: header, cookie, query param.
		var providedToken string
		auth := r.Header.Get("Authorization")
		if auth != "" {
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				providedToken = parts[1]
			}
		}

		// Check session cookie (set after successful ?token= auth)
		if providedToken == "" {
			if c, err := r.Cookie(sessionCookieName); err == nil {
				if crypto.ConstantTimeEqual([]byte(c.Value), []byte(sessionValue)) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Check ?token= query param (browser initial load)
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

		// On successful ?token= auth, set a session cookie so subsequent
		// requests (asset loads, API fetches) don't need the query param.
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    sessionValue,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
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
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")

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
