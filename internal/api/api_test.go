package api

import (
	"bytes"
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

func TestSendMessageMalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)

	// Send malformed JSON
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/api/messages/send", srv.Addr()),
		bytes.NewBufferString(`{not valid json`))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for malformed JSON, got %d", resp.StatusCode)
	}

	var env Envelope
	json.NewDecoder(resp.Body).Decode(&env)
	if env.OK {
		t.Error("expected ok=false for malformed JSON")
	}
}

func TestSendMessageMissingFields(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)

	// Empty content
	body := `{"channel_id":"aabbccdd","content":""}`
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/api/messages/send", srv.Addr()),
		bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for empty content, got %d", resp.StatusCode)
	}

	// Missing channel_id
	body2 := `{"content":"hello"}`
	req2, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/api/messages/send", srv.Addr()),
		bytes.NewBufferString(body2))
	req2.Header.Set("Authorization", "Bearer "+srv.Token())
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 400 {
		t.Errorf("expected 400 for missing channel_id, got %d", resp2.StatusCode)
	}
}

func TestChannelCreateDuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	srv, _ := setupTestServer(t)
	base := fmt.Sprintf("http://%s", srv.Addr())
	token := srv.Token()

	// setupTestServer already bootstrapped via conn.Bootstrap — no need to
	// re-bootstrap through the API (which now requires a real Slack token).

	// Create a channel
	chBody := `{"name":"dup-test-channel","description":"test","type":"public"}`
	req, _ := http.NewRequest("POST", base+"/api/channels/create",
		bytes.NewBufferString(chBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("first create should succeed, got %d", resp.StatusCode)
	}

	// Try to create same channel again
	req2, _ := http.NewRequest("POST", base+"/api/channels/create",
		bytes.NewBufferString(chBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 409 {
		t.Errorf("expected 409 for duplicate channel name, got %d", resp2.StatusCode)
	}

	var env Envelope
	json.NewDecoder(resp2.Body).Decode(&env)
	if env.OK {
		t.Error("expected ok=false for duplicate channel name")
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
