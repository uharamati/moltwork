package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorSatisfiesInterface(t *testing.T) {
	var err error = New("test.code", Fatal, "test message", nil)
	if err.Error() != "test.code: test message" {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := fmt.Errorf("underlying cause")
	mErr := Wrap(cause, "test.wrapped", Degraded, "wrapped message", nil)

	if !errors.Is(mErr, cause) {
		t.Error("errors.Is should find the cause")
	}

	var extracted *Error
	if !errors.As(mErr, &extracted) {
		t.Error("errors.As should extract *Error")
	}
	if extracted.Code != "test.wrapped" {
		t.Errorf("unexpected code: %s", extracted.Code)
	}
}

func TestIsError(t *testing.T) {
	mErr := New("test.is", Transient, "msg", nil)
	got, ok := IsError(mErr)
	if !ok {
		t.Fatal("IsError should return true for *Error")
	}
	if got.Code != "test.is" {
		t.Errorf("unexpected code: %s", got.Code)
	}

	_, ok = IsError(fmt.Errorf("plain error"))
	if ok {
		t.Error("IsError should return false for plain error")
	}
}

func TestIsErrorWrapped(t *testing.T) {
	mErr := New("inner.code", Fatal, "inner", nil)
	wrapped := fmt.Errorf("outer: %w", mErr)

	got, ok := IsError(wrapped)
	if !ok {
		t.Fatal("IsError should find *Error through wrapping")
	}
	if got.Code != "inner.code" {
		t.Errorf("unexpected code: %s", got.Code)
	}
}

func TestUnknown(t *testing.T) {
	cause := fmt.Errorf("something broke")
	mErr := Unknown("gossip", "sync", cause)

	if mErr.Code != "gossip.sync.unknown" {
		t.Errorf("unexpected code: %s", mErr.Code)
	}
	if mErr.Severity != Degraded {
		t.Errorf("unknown should be degraded, got %s", mErr.Severity)
	}
	if !errors.Is(mErr, cause) {
		t.Error("should wrap the cause")
	}
}

func TestWithOnboardingStep(t *testing.T) {
	e := New("onboarding.test", Fatal, "test", nil)
	e = WithOnboardingStep(e, 7, []int{1, 2, 3, 4, 5, 6})

	if e.Detail["onboarding_step"] != 7 {
		t.Errorf("expected step 7, got %v", e.Detail["onboarding_step"])
	}
	completed, ok := e.Detail["onboarding_completed"].([]int)
	if !ok || len(completed) != 6 {
		t.Errorf("expected 6 completed steps, got %v", e.Detail["onboarding_completed"])
	}
}

func TestDetailBuilderBlocklist(t *testing.T) {
	blocked := []string{
		"private_key", "secret_key", "shared_secret", "pairwise_secret",
		"group_key", "psk", "token", "platform_token", "passphrase",
		"password", "bearer",
	}

	for _, key := range blocked {
		t.Run(key, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Set(%q) should panic", key)
				}
			}()
			NewDetail().Set(key, "value")
		})
	}
}

func TestDetailBuilderAllowsSafeKeys(t *testing.T) {
	d := NewDetail().
		Set("agent_name", "Alice").
		Set("channel_name", "#general").
		Set("step", 5).
		Set("count", 3).
		Build()

	if d["agent_name"] != "Alice" {
		t.Error("safe keys should be allowed")
	}
	if len(d) != 4 {
		t.Errorf("expected 4 entries, got %d", len(d))
	}
}

func TestDetailBuilderEmptyReturnsNil(t *testing.T) {
	d := NewDetail().Build()
	if d != nil {
		t.Error("empty builder should return nil")
	}
}

func TestCatalogFunctions(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		code string
		sev  Severity
	}{
		{"PlatformAuthTestTimeout", PlatformAuthTestTimeout(), "platform.auth_test.timeout", Transient},
		{"PlatformAuthTestTokenInvalid", PlatformAuthTestTokenInvalid(), "platform.auth_test.token_invalid", Fatal},
		{"OnboardingDuplicatePlatformID", OnboardingDuplicatePlatformID(), "onboarding.duplicate.platform_id_exists", Fatal},
		{"MessageRateLimited", MessageRateLimited(30), "message.rate_limited", Degraded},
		{"MessageDestinationNotFound", MessageDestinationNotFound(), "message.destination.not_found", Fatal},
		{"GossipSyncNoPeers", GossipSyncNoPeers(), "gossip.sync.no_peers", Degraded},
		{"StorageIntegrityLogCorrupted", StorageIntegrityLogCorrupted(), "storage.integrity.log_corrupted", Fatal},
		{"ConnectorStartupPortInUse", ConnectorStartupPortInUse(), "connector.startup.port_in_use", Fatal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.code {
				t.Errorf("code: got %s, want %s", tt.err.Code, tt.code)
			}
			if tt.err.Severity != tt.sev {
				t.Errorf("severity: got %s, want %s", tt.err.Severity, tt.sev)
			}
			if tt.err.HumanMessage == "" {
				t.Error("human message should not be empty")
			}
		})
	}
}

func TestDomainMismatchDetail(t *testing.T) {
	e := PlatformAuthTestDomainMismatch("wrong.slack.com", "correct.slack.com")
	if e.Detail["returned_domain"] != "wrong.slack.com" {
		t.Error("should include returned domain in detail")
	}
	if e.Detail["expected_domain"] != "correct.slack.com" {
		t.Error("should include expected domain in detail")
	}
}
