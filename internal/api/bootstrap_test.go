package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"moltwork/internal/config"
	"moltwork/internal/connector"
	"moltwork/internal/identity"
	"moltwork/internal/rendezvous"
)

// stubRendezvous is a test stub for rendezvous.Provider that only implements
// WorkspaceExists. All other methods panic — the bootstrap handler should not
// call them.
type stubRendezvous struct {
	exists bool
	err    error
}

func (s *stubRendezvous) WorkspaceExists(ctx context.Context) (bool, error) {
	return s.exists, s.err
}
func (s *stubRendezvous) PostGossipAddress(ctx context.Context, addr rendezvous.GossipAddress) error {
	panic("unexpected")
}
func (s *stubRendezvous) GetGossipAddresses(ctx context.Context) ([]rendezvous.GossipAddress, error) {
	panic("unexpected")
}
func (s *stubRendezvous) PostJoinRequest(ctx context.Context, req rendezvous.JoinRequest) (string, error) {
	panic("unexpected")
}
func (s *stubRendezvous) WatchForJoinResponse(ctx context.Context, requestID string, timeout time.Duration) (*rendezvous.JoinResponse, error) {
	panic("unexpected")
}
func (s *stubRendezvous) WatchForJoinRequests(ctx context.Context) (<-chan rendezvous.JoinRequest, error) {
	panic("unexpected")
}
func (s *stubRendezvous) PostJoinResponse(ctx context.Context, requestID string, resp rendezvous.JoinResponse) error {
	panic("unexpected")
}
func (s *stubRendezvous) ClaimJoinRequest(ctx context.Context, requestID string, claimerKey []byte) (bool, error) {
	panic("unexpected")
}
func (s *stubRendezvous) DeleteMessages(ctx context.Context, messageIDs []string) error {
	panic("unexpected")
}
func (s *stubRendezvous) ChannelID() string { return "" }

// newBootstrapTestServer builds an API server with no prior bootstrap state
// and installs stubbed token verification + rendezvous provider so the
// handler's guard can be exercised without hitting Slack.
func newBootstrapTestServer(t *testing.T, rv rendezvous.Provider, verifyErr error) *Server {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	dir, err := os.MkdirTemp("", "moltwork-bootstrap-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	cfg := config.Default()
	cfg.DataDir = dir
	cfg.ListenPort = 0

	conn := connector.New(cfg)
	if err := conn.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	srv, err := NewServer(conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv.verifyPlatformToken = func(ctx context.Context, platform, tok string) (*identity.PlatformIdentity, error) {
		if verifyErr != nil {
			return nil, verifyErr
		}
		return &identity.PlatformIdentity{
			Platform:        "slack",
			WorkspaceDomain: "test.slack.com",
		}, nil
	}
	srv.newRendezvous = func(platform, tok string) rendezvous.Provider {
		return rv
	}
	srv.Start()
	t.Cleanup(func() { srv.Close() })
	return srv
}

func postBootstrap(t *testing.T, srv *Server, body string) (*http.Response, map[string]any) {
	t.Helper()
	resp := doPost(t, fmt.Sprintf("http://%s/api/bootstrap", srv.Addr()), srv.Token(), body)
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	resp.Body.Close()
	out := map[string]any{"ok": env.OK}
	if env.OK {
		if m, ok := env.Result.(map[string]any); ok {
			for k, v := range m {
				out[k] = v
			}
		}
	} else if env.Error != nil {
		out["code"] = env.Error.ErrorCode
		out["message"] = env.Error.HumanMessage
	}
	return resp, out
}

func TestBootstrap_MissingToken(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	srv := newBootstrapTestServer(t, &stubRendezvous{exists: false}, nil)

	body := `{"platform":"slack","workspace_domain":"test.slack.com"}`
	resp, env := postBootstrap(t, srv, body)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for missing platform_token, got %d", resp.StatusCode)
	}
	if code, _ := env["code"].(string); code != "onboarding.bootstrap.missing_fields" {
		t.Errorf("expected missing_fields code, got %q", code)
	}
}

func TestBootstrap_BadToken(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	srv := newBootstrapTestServer(t, &stubRendezvous{exists: false}, errors.New("invalid_auth"))

	body := `{"platform":"slack","workspace_domain":"test.slack.com","platform_token":"xoxb-bad"}`
	resp, env := postBootstrap(t, srv, body)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for bad token, got %d", resp.StatusCode)
	}
	if code, _ := env["code"].(string); code != "onboarding.bootstrap.token_invalid" {
		t.Errorf("expected token_invalid code, got %q", code)
	}
}

func TestBootstrap_WorkspaceAlreadyExists(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	srv := newBootstrapTestServer(t, &stubRendezvous{exists: true}, nil)

	body := `{"platform":"slack","workspace_domain":"test.slack.com","platform_token":"xoxb-ok"}`
	resp, env := postBootstrap(t, srv, body)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 when workspace exists, got %d", resp.StatusCode)
	}
	code, _ := env["code"].(string)
	if code != "onboarding.bootstrap.workspace_exists" {
		t.Errorf("expected workspace_exists code, got %q", code)
	}
	if msg, _ := env["message"].(string); !strings.Contains(msg, "join/rendezvous") {
		t.Errorf("expected message to point at join/rendezvous, got %q", msg)
	}
}

func TestBootstrap_RendezvousCheckError(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	srv := newBootstrapTestServer(t, &stubRendezvous{err: errors.New("slack timeout")}, nil)

	body := `{"platform":"slack","workspace_domain":"test.slack.com","platform_token":"xoxb-ok"}`
	resp, env := postBootstrap(t, srv, body)
	if resp.StatusCode != 502 {
		t.Fatalf("expected 502 when rendezvous check errors, got %d", resp.StatusCode)
	}
	if code, _ := env["code"].(string); code != "onboarding.bootstrap.rendezvous_check_failed" {
		t.Errorf("expected rendezvous_check_failed code, got %q", code)
	}
}

func TestBootstrap_Success(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	srv := newBootstrapTestServer(t, &stubRendezvous{exists: false}, nil)

	body := `{"platform":"slack","workspace_domain":"test.slack.com","platform_token":"xoxb-ok"}`
	resp, env := postBootstrap(t, srv, body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 on fresh bootstrap, got %d (env=%v)", resp.StatusCode, env)
	}
	if ok, _ := env["ok"].(bool); !ok {
		t.Errorf("expected ok=true")
	}
	if status, _ := env["status"].(string); status != "bootstrapped" {
		t.Errorf("expected bootstrapped, got %q", status)
	}
}
