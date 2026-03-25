package logging

import "testing"

func TestRedactFields(t *testing.T) {
	fields := map[string]any{
		"private_key":     "key-bytes",
		"shared_secret":   "secret-bytes",
		"psk":             "psk-value",
		"token":           "tok-123",
		"platform_token":  "xoxb-abc",
		"passphrase":      "hunter2",
		"username":        "alice",
		"peer_count":      5,
	}

	safe := RedactFields(fields)

	for _, key := range []string{"private_key", "shared_secret", "psk", "token", "platform_token", "passphrase"} {
		if safe[key] != "[REDACTED]" {
			t.Errorf("%s should be redacted, got %v", key, safe[key])
		}
	}

	if safe["username"] != "alice" {
		t.Errorf("username should not be redacted")
	}
	if safe["peer_count"] != 5 {
		t.Errorf("peer_count should not be redacted")
	}
}

func TestRedactFieldsNil(t *testing.T) {
	if RedactFields(nil) != nil {
		t.Error("nil input should return nil")
	}
}
