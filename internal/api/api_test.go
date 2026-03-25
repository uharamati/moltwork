package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"moltwork/internal/config"
	"moltwork/internal/connector"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "moltwork-api-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func setupTestServer(t *testing.T) (*Server, *connector.Connector) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := connector.New(cfg)
	if err := conn.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	conn.Bootstrap("slack", "test.slack.com")

	srv, err := NewServer(conn, 0) // port 0 = random
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	t.Cleanup(func() { srv.Close() })

	return srv, conn
}

func TestStatusEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/status", srv.Addr()), nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var env Envelope
	json.NewDecoder(resp.Body).Decode(&env)

	if !env.OK {
		t.Error("expected ok=true")
	}
	if env.CorrelationID == "" {
		t.Error("expected correlation_id to be set")
	}

	result, ok := env.Result.(map[string]any)
	if !ok {
		t.Fatal("result should be a map")
	}
	if result["status"] != "running" {
		t.Errorf("expected running, got %v", result["status"])
	}
}

func TestChannelsEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/channels", srv.Addr()), nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var env Envelope
	json.NewDecoder(resp.Body).Decode(&env)

	if !env.OK {
		t.Error("expected ok=true")
	}

	// Result is an array of channels wrapped in the envelope
	channels, ok := env.Result.([]any)
	if !ok {
		t.Fatal("result should be an array")
	}
	if len(channels) != 4 {
		t.Errorf("expected 4 channels, got %d", len(channels))
	}
}

func TestUnauthorizedRejected(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)

	// No auth header
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/status", srv.Addr()), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("no auth: expected 401, got %d", resp.StatusCode)
	}

	// Wrong token
	req, _ = http.NewRequest("GET", fmt.Sprintf("http://%s/api/status", srv.Addr()), nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("wrong token: expected 401, got %d", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/status", srv.Addr()), nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	checks := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	for header, expected := range checks {
		got := resp.Header.Get(header)
		if got != expected {
			t.Errorf("%s: got %q, want %q", header, got, expected)
		}
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Error("missing CSP header")
	}
}
