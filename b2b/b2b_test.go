package b2b

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func createMockToken(header map[string]interface{}, payload map[string]interface{}) string {
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)

	hB64 := base64.RawURLEncoding.EncodeToString(hBytes)
	pB64 := base64.RawURLEncoding.EncodeToString(pBytes)

	return hB64 + "." + pB64 + ".mockSignature"
}

func TestB2BModule_ValidateToken_Claims(t *testing.T) {
	mod := NewModule("https://auth.acme.com")

	now := time.Now().Unix()
	token := createMockToken(
		map[string]interface{}{"alg": "RS256", "kid": "k1"},
		map[string]interface{}{
			"sub":         "usr_go_123",
			"tenant_id":   "ten_enterprise",
			"email":       "go_dev@acme.com",
			"roles":       []interface{}{"admin", "developer"},
			"permissions": []interface{}{"org:read", "org:write", "users:*"},
			"iss":         "https://auth.acme.com",
			"exp":         float64(now + 3600),
		},
	)

	user, err := mod.ValidateToken(context.Background(), token, TokenValidationOptions{
		SkipSignatureCheck: true,
	})
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if user.UserID != "usr_go_123" {
		t.Errorf("expected UserID usr_go_123, got %s", user.UserID)
	}
	if user.TenantID != "ten_enterprise" {
		t.Errorf("expected TenantID ten_enterprise, got %s", user.TenantID)
	}
	if user.Email != "go_dev@acme.com" {
		t.Errorf("expected Email go_dev@acme.com, got %s", user.Email)
	}

	// RBAC checks
	if !mod.HasPermission(user, "org:read") {
		t.Error("expected hasPermission org:read to be true")
	}
	if !mod.HasPermission(user, "users:create") {
		t.Error("expected wildcard users:* to grant users:create")
	}
	if mod.HasPermission(user, "billing:write") {
		t.Error("expected billing:write to be false")
	}

	if !mod.HasRole(user, "admin") {
		t.Error("expected hasRole admin to be true")
	}
	if mod.HasRole(user, "superadmin") {
		t.Error("expected hasRole superadmin to be false")
	}
}

func TestB2BModule_ValidateToken_Expired(t *testing.T) {
	mod := NewModule("https://auth.acme.com")

	now := time.Now().Unix()
	token := createMockToken(
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{
			"sub": "usr_expired",
			"exp": float64(now - 120),
		},
	)

	_, err := mod.ValidateToken(context.Background(), token, TokenValidationOptions{
		SkipSignatureCheck: true,
		ClockTolerance:     10 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}
