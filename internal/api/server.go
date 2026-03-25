package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"moltwork/internal/connector"
	"moltwork/internal/crypto"
	"moltwork/internal/health"
	"moltwork/internal/logging"
	"moltwork/internal/store"
)

// Server is the HTTP API for the web UI and OpenClaw connector.
type Server struct {
	conn          *connector.Connector
	log           *logging.Logger
	server        *http.Server
	mux           *http.ServeMux
	token         string
	listener      net.Listener
	healthChecker *health.Checker
	diagDB        *store.DiagDB
	version       string
	frontend      http.Handler
	syncSessions  *syncSessionStore
	syncLimiter   *authRateLimiter
}

// SetVersion sets the version string for the status endpoint.
func (s *Server) SetVersion(v string) {
	s.version = v
}

// NewServer creates an API server bound to 127.0.0.1 only (rule N1).
func NewServer(conn *connector.Connector, port int) (*Server, error) {
	// Generate ephemeral 256-bit bearer token (rule N2)
	tokenBytes := crypto.RandomBytes(32)
	token := hex.EncodeToString(tokenBytes)

	// Write token to file with 0600 permissions (rule N2)
	tokenPath := conn.WebUITokenPath()
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return nil, fmt.Errorf("write token file: %w", err)
	}

	log := logging.New("api")

	s := &Server{
		conn:         conn,
		log:          log,
		token:        token,
		syncSessions: newSyncSessionStore(),
		syncLimiter:  newAuthRateLimiter(5, time.Minute),
	}

	mux := http.NewServeMux()
	s.mux = mux
	s.registerRoutes(mux)
	s.registerConnectorRoutes(mux)
	s.registerSyncRoutes(mux)
	s.registerDiagnosticsRoutes(mux)

	// Bind to 127.0.0.1 only (rule N1)
	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", bindAddr, err)
	}
	s.listener = listener

	// Add security.txt endpoint (rule G6)
	mux.HandleFunc("GET /.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Contact: https://github.com/moltwork/moltwork/security")
		fmt.Fprintln(w, "Preferred-Languages: en")
	})

	s.server = &http.Server{
		Handler:      correlationMiddleware(securityHeaders(authMiddleware(mux, token, log))),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s, nil
}

// Start begins serving. Non-blocking.
func (s *Server) Start() {
	go func() {
		s.log.Info("API server started", map[string]any{
			"address": s.listener.Addr().String(),
		})
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			s.log.Error("API server error", map[string]any{"error": err.Error()})
		}
	}()
}

// Addr returns the server's listen address.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Token returns the bearer token for API authentication.
func (s *Server) Token() string {
	return s.token
}

// SetHealthChecker sets the health checker after construction.
func (s *Server) SetHealthChecker(hc *health.Checker) {
	s.healthChecker = hc
}

// SetDiagDB sets the diagnostics database after construction.
func (s *Server) SetDiagDB(db *store.DiagDB) {
	s.diagDB = db
}

// registerDiagnosticsRoutes registers health, logs, and diagnostics endpoints.
func (s *Server) registerDiagnosticsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/logs/query", s.handleLogsQuery)
	mux.HandleFunc("GET /api/diagnostics/bundle", s.handleDiagnosticsBundle)
}

// Close gracefully shuts down the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}
