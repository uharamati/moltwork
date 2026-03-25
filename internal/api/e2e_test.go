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

// decodeEnvelope decodes an envelope response and returns the result as a map.
func decodeEnvelope(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok=true, got error: %+v", env.Error)
	}
	result, ok := env.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not a map: %T", env.Result)
	}
	return result
}

// decodeEnvelopeArray decodes an envelope response where result is an array.
func decodeEnvelopeArray(t *testing.T, resp *http.Response) []any {
	t.Helper()
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("expected ok=true, got error: %+v", env.Error)
	}
	result, ok := env.Result.([]any)
	if !ok {
		t.Fatalf("result is not an array: %T", env.Result)
	}
	return result
}

// TestEndToEnd exercises the full flow an OpenClaw agent would perform:
// bootstrap -> join -> send message -> read messages -> poll activity
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Set up connector + API server
	dir, _ := os.MkdirTemp("", "moltwork-e2e-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

	cfg := config.Default()
	cfg.DataDir = dir
	cfg.ListenPort = 0

	conn := connector.New(cfg)
	if err := conn.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srv, err := NewServer(conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	defer srv.Close()

	base := fmt.Sprintf("http://%s", srv.Addr())
	token := srv.Token()

	// --- Step 1: Check status (should be empty) ---
	resp := doGet(t, base+"/api/status", token)
	status := decodeEnvelope(t, resp)
	resp.Body.Close()

	if status["status"] != "running" {
		t.Fatalf("expected running, got %v", status["status"])
	}
	t.Log("Step 1: Status OK")

	// --- Step 2: Bootstrap workspace ---
	body := `{"platform":"slack","workspace_domain":"test.slack.com"}`
	resp = doPost(t, base+"/api/bootstrap", token, body)
	bsResult := decodeEnvelope(t, resp)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("bootstrap failed: %d", resp.StatusCode)
	}
	if bsResult["status"] != "bootstrapped" {
		t.Fatalf("expected bootstrapped, got %v", bsResult["status"])
	}
	t.Log("Step 2: Bootstrap OK")

	// --- Step 3: Join as an agent ---
	joinBody := `{"display_name":"Test Agent","platform":"slack","platform_user_id":"U999","title":"QA Engineer","team":"Testing"}`
	resp = doPost(t, base+"/api/join", token, joinBody)
	joinResult := decodeEnvelope(t, resp)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("join failed: %d", resp.StatusCode)
	}
	if joinResult["status"] != "joined" {
		t.Fatalf("expected joined, got %v", joinResult["status"])
	}
	t.Log("Step 3: Join OK")

	// --- Step 4: List channels ---
	resp = doGet(t, base+"/api/channels", token)
	channels := decodeEnvelopeArray(t, resp)
	resp.Body.Close()

	if len(channels) != 4 {
		t.Fatalf("expected 4 channels, got %d", len(channels))
	}

	// Find #general
	var generalID string
	for _, raw := range channels {
		ch, _ := raw.(map[string]any)
		if ch["name"] == "general" {
			generalID = ch["id"].(string)
		}
	}
	if generalID == "" {
		t.Fatal("general channel not found")
	}
	t.Log("Step 4: Channels OK, found #general:", generalID[:16]+"...")

	// --- Step 5: Send a message ---
	msgBody := fmt.Sprintf(`{"channel_id":"%s","content":"Hello from the e2e test! Coordination starting.","message_type":0}`, generalID)
	resp = doPost(t, base+"/api/messages/send", token, msgBody)
	sendResult := decodeEnvelope(t, resp)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("send failed: %d", resp.StatusCode)
	}
	if sendResult["status"] != "sent" {
		t.Fatalf("expected sent, got %v", sendResult["status"])
	}
	t.Log("Step 5: Message sent OK")

	// --- Step 6: Read messages from #general ---
	resp = doGet(t, base+"/api/messages/"+generalID+"?since=0", token)
	msgsEnv := decodeEnvelopeArray(t, resp)
	resp.Body.Close()

	// Should have at least the message we just sent
	found := false
	for _, raw := range msgsEnv {
		msg, _ := raw.(map[string]any)
		content, _ := msg["content"].(string)
		if content == "Hello from the e2e test! Coordination starting." {
			found = true
			t.Logf("Step 6: Found our message, author=%v", msg["author_name"])
		}
	}
	if !found {
		t.Fatalf("our message not found in channel messages. Got %d messages", len(msgsEnv))
	}

	// --- Step 7: Poll activity ---
	resp = doGet(t, base+"/api/activity?since=0", token)
	activity := decodeEnvelope(t, resp)
	resp.Body.Close()

	activityMsgs, _ := activity["messages"].([]any)
	if len(activityMsgs) == 0 {
		t.Fatal("expected activity messages")
	}
	latestTs, _ := activity["latest_timestamp"].(float64)
	if latestTs == 0 {
		t.Fatal("expected non-zero latest_timestamp")
	}
	t.Logf("Step 7: Activity poll OK, %d messages, latest_timestamp=%v", len(activityMsgs), latestTs)

	// --- Step 8: Get identity ---
	resp = doGet(t, base+"/api/identity", token)
	ident := decodeEnvelope(t, resp)
	resp.Body.Close()

	if ident["public_key"] == nil || ident["public_key"] == "" {
		t.Fatal("expected public_key in identity")
	}
	t.Logf("Step 8: Identity OK, key=%v", ident["public_key"].(string)[:16]+"...")

	// --- Step 9: List agents ---
	resp = doGet(t, base+"/api/agents", token)
	agents := decodeEnvelopeArray(t, resp)
	resp.Body.Close()

	if len(agents) == 0 {
		t.Fatal("expected at least 1 agent")
	}
	t.Logf("Step 9: Agents OK, count=%d", len(agents))

	// --- Step 10: Create a new channel ---
	chBody := `{"name":"e2e-test-channel","description":"Created by e2e test","type":"public"}`
	resp = doPost(t, base+"/api/channels/create", token, chBody)
	chResult := decodeEnvelope(t, resp)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("create channel failed: %d", resp.StatusCode)
	}
	t.Logf("Step 10: Channel created: %v", chResult["name"])

	// --- Step 11: Health endpoint ---
	resp = doGet(t, base+"/api/health", token)
	var healthResp map[string]any
	json.NewDecoder(resp.Body).Decode(&healthResp)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("health failed: %d", resp.StatusCode)
	}
	t.Logf("Step 11: Health OK, status=%v", healthResp["status"])

	// --- Step 12: Correlation ID in response ---
	resp = doGet(t, base+"/api/status", token)
	corrID := resp.Header.Get("X-Correlation-ID")
	resp.Body.Close()
	if corrID == "" {
		t.Error("expected X-Correlation-ID header")
	}
	t.Logf("Step 12: Correlation ID OK: %s", corrID[:8]+"...")

	// --- Step 13: Send thread reply ---
	// First find a message hash to reply to
	resp = doGet(t, base+"/api/messages/"+generalID+"?since=0", token)
	allMsgs := decodeEnvelopeArray(t, resp)
	resp.Body.Close()

	var parentHash string
	for _, raw := range allMsgs {
		msg, _ := raw.(map[string]any)
		if h, ok := msg["hash"].(string); ok && h != "" {
			parentHash = h
			break
		}
	}
	if parentHash == "" {
		t.Fatal("no message found to reply to")
	}

	threadBody := fmt.Sprintf(`{"channel_id":"%s","parent_hash":"%s","content":"Thread reply from e2e test"}`, generalID, parentHash)
	resp = doPost(t, base+"/api/threads/reply", token, threadBody)
	threadResult := decodeEnvelope(t, resp)
	resp.Body.Close()
	if threadResult["status"] != "sent" {
		t.Fatalf("expected sent, got %v", threadResult["status"])
	}
	t.Log("Step 13: Thread reply sent OK")

	// --- Step 14: Read thread replies ---
	resp = doGet(t, base+"/api/threads/"+parentHash+"?since=0", token)
	threadReplies := decodeEnvelopeArray(t, resp)
	resp.Body.Close()
	if len(threadReplies) == 0 {
		t.Fatal("expected thread replies")
	}
	t.Logf("Step 14: Thread replies OK, count=%d", len(threadReplies))

	// --- Step 15: Agent detail ---
	agentKey := ident["public_key"].(string)
	resp = doGet(t, base+"/api/agents/"+agentKey, token)
	agentDetail := decodeEnvelope(t, resp)
	resp.Body.Close()
	if agentDetail["public_key"] == nil {
		t.Fatal("expected public_key in agent detail")
	}
	if agentDetail["channels"] == nil {
		t.Fatal("expected channels in agent detail")
	}
	t.Logf("Step 15: Agent detail OK, name=%v", agentDetail["display_name"])

	// --- Step 16: Leave channel ---
	newChID := chResult["channel_id"].(string)
	// First join the new channel
	joinChBody := fmt.Sprintf(`{"channel_id":"%s"}`, newChID)
	resp = doPost(t, base+"/api/channels/join", token, joinChBody)
	decodeEnvelope(t, resp)
	resp.Body.Close()

	// Now leave it
	leaveBody := fmt.Sprintf(`{"channel_id":"%s"}`, newChID)
	resp = doPost(t, base+"/api/channels/leave", token, leaveBody)
	leaveResult := decodeEnvelope(t, resp)
	resp.Body.Close()
	if leaveResult["status"] != "left" {
		t.Fatalf("expected left, got %v", leaveResult["status"])
	}
	t.Log("Step 16: Channel leave OK")

	// --- Step 17: Org relationships endpoint ---
	resp = doGet(t, base+"/api/org/relationships", token)
	orgRels := decodeEnvelopeArray(t, resp)
	resp.Body.Close()
	t.Logf("Step 17: Org relationships OK, count=%d", len(orgRels))

	// --- Step 18: Attestations endpoint ---
	resp = doGet(t, base+"/api/attestations", token)
	attestations := decodeEnvelopeArray(t, resp)
	resp.Body.Close()
	t.Logf("Step 18: Attestations OK, count=%d", len(attestations))

	// --- Step 19: Action request validation ---
	// Action request without action field should fail
	badAction := fmt.Sprintf(`{"channel_id":"%s","content":"do something","message_type":1}`, generalID)
	resp = doPost(t, base+"/api/messages/send", token, badAction)
	var errEnv Envelope
	json.NewDecoder(resp.Body).Decode(&errEnv)
	resp.Body.Close()
	if errEnv.OK {
		t.Error("expected action request without action field to fail")
	}
	t.Log("Step 19: Action request validation OK (rejected missing action field)")

	// Action request with action field should succeed
	goodAction := fmt.Sprintf(`{"channel_id":"%s","content":"please review","message_type":1,"action":"review_pr","scope":"engineering","authority_basis":"team_lead"}`, generalID)
	resp = doPost(t, base+"/api/messages/send", token, goodAction)
	actionResult := decodeEnvelope(t, resp)
	resp.Body.Close()
	if actionResult["status"] != "sent" {
		t.Fatalf("valid action request should succeed, got %v", actionResult["status"])
	}
	t.Log("Step 20: Action request with fields sent OK")

	// --- Step 21: Capability declaration ---
	capBody := `{"capabilities":["read_email","search_docs"],"restrictions":["no_send_email"]}`
	resp = doPost(t, base+"/api/capabilities/declare", token, capBody)
	capResult := decodeEnvelope(t, resp)
	resp.Body.Close()
	if capResult["status"] != "declared" {
		t.Fatalf("expected declared, got %v", capResult["status"])
	}
	t.Log("Step 21: Capability declaration OK")

	// --- Step 22: Read capabilities ---
	resp = doGet(t, base+"/api/capabilities/"+agentKey, token)
	capReadResult := decodeEnvelope(t, resp)
	resp.Body.Close()
	caps, _ := capReadResult["capabilities"].([]any)
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}
	t.Log("Step 22: Capability read OK")

	// --- Step 23: Activity includes multiple types ---
	resp = doGet(t, base+"/api/activity?since=0&limit=1000", token)
	activityFull := decodeEnvelope(t, resp)
	resp.Body.Close()
	allActivity, _ := activityFull["messages"].([]any)
	activityTypes := make(map[string]bool)
	for _, raw := range allActivity {
		item, _ := raw.(map[string]any)
		if at, ok := item["activity_type"].(string); ok && at != "" {
			activityTypes[at] = true
		}
	}
	if !activityTypes["message"] {
		t.Error("activity should include 'message' type")
	}
	if !activityTypes["channel_create"] {
		t.Error("activity should include 'channel_create' type")
	}
	t.Logf("Step 23: Activity types seen: %v", activityTypes)

	t.Log("=== END-TO-END TEST PASSED ===")
}

func doGet(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func doPost(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
