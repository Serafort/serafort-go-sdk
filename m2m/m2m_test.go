package m2m

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenCache_GetSet(t *testing.T) {
	cache := NewTokenCache(5 * time.Minute)

	cache.Set("client_1", "tok_valid", 10*time.Minute, "")
	tok, ok := cache.Get("client_1")
	if !ok || tok != "tok_valid" {
		t.Fatalf("expected valid token, got ok=%v, tok=%s", ok, tok)
	}

	// Test token nearing expiration within buffer (4 minutes < 5 minutes buffer)
	cache.Set("client_2", "tok_expiring", 4*time.Minute, "")
	_, ok = cache.Get("client_2")
	if ok {
		t.Fatalf("expected token nearing expiration to be invalid due to proactive buffer")
	}
}

func TestM2MModule_GetAccessToken_SuccessAndCache(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuthResponse{
			AccessToken: "m2m_secret_token_123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	mod := NewModule(server.URL, "client_id_1", "client_secret_1", "")
	mod.SetHTTPClient(server.Client())

	ctx := context.Background()

	// First call -> hits server
	tok1, err := mod.GetAccessToken(ctx, []string{"read:users"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 != "m2m_secret_token_123" {
		t.Fatalf("unexpected token: %s", tok1)
	}

	// Second call -> hits cache
	tok2, err := mod.GetAccessToken(ctx, []string{"read:users"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok2 != "m2m_secret_token_123" {
		t.Fatalf("unexpected token: %s", tok2)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected 1 network request due to cache, got %d", requestCount)
	}
}

func TestM2MModule_ThunderingHerd(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuthResponse{
			AccessToken: "coalesced_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	mod := NewModule(server.URL, "c_id", "c_secret", "")
	mod.SetHTTPClient(server.Client())

	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := mod.GetAccessToken(ctx, nil)
			if err != nil || tok != "coalesced_token" {
				t.Errorf("expected coalesced_token, got %s, err=%v", tok, err)
			}
		}()
	}

	wg.Wait()

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected exactly 1 server request for coalesced concurrent calls, got %d", requestCount)
	}
}
