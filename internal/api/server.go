package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"moltwork/internal/connector"
	"moltwork/internal/crypto"
	"moltwork/internal/gossip"
	"moltwork/internal/health"
	"moltwork/internal/identity"
	"moltwork/internal/logging"
	"moltwork/internal/rendezvous"
	"moltwork/internal/store"
)

// joinStatusEntry tracks the async status of a join operation.
type joinStatusEntry struct {
	Status   string `json:"status"`   // "joining", "joined", "failed"
	Error    string `json:"error,omitempty"`
	AgentKey string `json:"agent_key,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// Server is the HTTP API for the web UI and OpenClaw connector.
type Server struct {
	conn           *connector.Connector
	log            *logging.Logger
	server         *http.Server
	mux            *http.ServeMux
	token          string
	listener       net.Listener
	healthChecker  *health.Checker
	diagDB         *store.DiagDB
	version        string
	frontend       http.Handler
	skillFS        fs.FS
	syncSessions   *syncSessionStore
	syncLimiter    *authRateLimiter
	dmLimiter      *gossip.RateLimiter // per-recipient DM rate limit (BUG-22)
	writeLimiter   *gossip.RateLimiter // per-agent write rate limit (30/min)
	dmCooldownMu   sync.Mutex
	dmLastSent     map[string]time.Time // recipient_key -> last DM time (60s reply cooldown)
	sseConnections int32                // atomic counter for active SSE connections
	publicServer   *http.Server
	publicListener net.Listener
	joinStatuses   sync.Map // joinID -> *joinStatusEntry

	// Test seams. Overridable so unit tests can bypass real Slack calls.
	// Defaults are set in NewServer.
	verifyPlatformToken func(ctx context.Context, platform, token string) (*identity.PlatformIdentity, error)
	newRendezvous       func(platform, token string) rendezvous.Provider
}

// SetVersion sets the version string for the status endpoint.
func (s *Server) SetVersion(v string) {
	s.version = v
}

// NewServer creates an API server bound to 127.0.0.1 only (rule N1).
func NewServer(conn *connector.Connector, port int) (*Server, error) {
	// Persist token across restarts — reuse existing token if available (bug 9).
	// Only generate a new token if the file doesn't exist or is empty.
	tokenPath := conn.WebUITokenPath()
	var token string
	if existing, err := os.ReadFile(tokenPath); err == nil && len(existing) > 0 {
		token = strings.TrimSpace(string(existing))
	}
	if token == "" {
		tokenBytes := crypto.RandomBytes(32)
		token = hex.EncodeToString(tokenBytes)
		if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
			return nil, fmt.Errorf("write token file: %w", err)
		}
	}

	log := logging.New("api")

	s := &Server{
		conn:         conn,
		log:          log,
		token:        token,
		syncSessions: newSyncSessionStore(),
		syncLimiter:  newAuthRateLimiter(5, time.Minute),
		dmLimiter:    gossip.NewRateLimiter(5, time.Minute),  // 5 DMs/min per recipient (BUG-22)
		writeLimiter: gossip.NewRateLimiter(30, time.Minute), // 30 writes/min per agent (matches gossip N6)
		dmLastSent:   make(map[string]time.Time),
		verifyPlatformToken: func(ctx context.Context, platform, tok string) (*identity.PlatformIdentity, error) {
			switch platform {
			case "slack":
				return identity.NewSlackVerifier().Verify(ctx, tok)
			default:
				return nil, fmt.Errorf("unsupported platform: %s", platform)
			}
		},
		newRendezvous: func(platform, tok string) rendezvous.Provider {
			return rendezvous.NewSlackProvider(tok, log)
		},
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
		if isAddrInUse(err) {
			return nil, fmt.Errorf("listen %s: address already in use — another moltwork instance may be running on this port", bindAddr)
		}
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
		WriteTimeout: 0, // SSE and long-poll handlers manage their own timeouts
		IdleTimeout:  2 * time.Minute,
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

// StartPublicSync starts a second HTTP server on 0.0.0.0:{port} that only
// serves the /api/sync/* endpoints. This allows external agents to reach
// the sync endpoints while the main API stays on localhost.
func (s *Server) StartPublicSync(port int) error {
	mux := http.NewServeMux()
	s.registerSyncRoutes(mux)

	bindAddr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", bindAddr, err)
	}
	s.publicListener = listener

	s.publicServer = &http.Server{
		Handler:      correlationMiddleware(securityHeaders(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		s.log.Info("public sync server started", map[string]any{
			"address": listener.Addr().String(),
		})
		if err := s.publicServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.log.Error("public sync server error", map[string]any{"error": err.Error()})
		}
	}()
	return nil
}

// isAddrInUse checks if a net.Listen error is "address already in use".
func isAddrInUse(err error) bool {
	return err != nil && strings.Contains(err.Error(), "address already in use")
}

// Close gracefully shuts down the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.publicServer != nil {
		s.publicServer.Shutdown(ctx)
	}
	return s.server.Shutdown(ctx)
}
