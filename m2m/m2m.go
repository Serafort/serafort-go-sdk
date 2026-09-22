package m2m

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type CachedToken struct {
	AccessToken string
	ExpiresAt   time.Time
	Scope       string
}

type TokenCache struct {
	mu           sync.RWMutex
	tokens       map[string]CachedToken
	bufferPeriod time.Duration
}

func NewTokenCache(bufferPeriod time.Duration) *TokenCache {
	return &TokenCache{
		tokens:       make(map[string]CachedToken),
		bufferPeriod: bufferPeriod,
	}
}

func (c *TokenCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.tokens[key]
	if !exists {
		return "", false
	}

	// Check if token has expired or is inside proactive refresh buffer
	if time.Now().Add(c.bufferPeriod).After(item.ExpiresAt) {
		return "", false
	}

	return item.AccessToken, true
}

func (c *TokenCache) Set(key, token string, expiresIn time.Duration, scope string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tokens[key] = CachedToken{
		AccessToken: token,
		ExpiresAt:   time.Now().Add(expiresIn),
		Scope:       scope,
	}
}

func (c *TokenCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, key)
}

type RetryConfig struct {
	MaxRetries     int
	InitialDelayMs int
	MaxDelayMs     int
}

type Module struct {
	endpoint     string
	clientID     string
	clientSecret string
	privateKey   string
	httpClient   *http.Client
	cache        *TokenCache
	retry        RetryConfig
	flightMu     sync.Mutex
	inFlight     map[string]chan struct{}
	lastToken    map[string]string
	lastErr      map[string]error
}

func NewModule(endpoint, clientID, clientSecret, privateKey string) *Module {
	return &Module{
		endpoint:     strings.TrimRight(endpoint, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		privateKey:   privateKey,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		cache:        NewTokenCache(5 * time.Minute), // 5 min proactive refresh buffer
		retry: RetryConfig{
			MaxRetries:     3,
			InitialDelayMs: 500,
			MaxDelayMs:     5000,
		},
		inFlight:  make(map[string]chan struct{}),
		lastToken: make(map[string]string),
		lastErr:   make(map[string]error),
	}
}

func (m *Module) SetHTTPClient(client *http.Client) {
	m.httpClient = client
}

type OAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type ErrorEnvelope struct {
	Status string `json:"status"`
	Error  struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error"`
}

func (m *Module) GetAccessToken(ctx context.Context, scopes []string) (string, error) {
	return m.getToken(ctx, scopes, false)
}

func (m *Module) ForceRefreshToken(ctx context.Context, scopes []string) (string, error) {
	return m.getToken(ctx, scopes, true)
}

func (m *Module) getToken(ctx context.Context, scopes []string, force bool) (string, error) {
	sortedScopes := make([]string, len(scopes))
	copy(sortedScopes, scopes)
	sort.Strings(sortedScopes)
	scopeKey := strings.Join(sortedScopes, " ")
	cacheKey := fmt.Sprintf("%s:%s", m.clientID, scopeKey)

	if !force {
		if token, valid := m.cache.Get(cacheKey); valid {
			return token, nil
		}
	}

	// Singleflight pattern to avoid thundering-herd on token refresh
	m.flightMu.Lock()
	if ch, running := m.inFlight[cacheKey]; running {
		m.flightMu.Unlock()
		select {
		case <-ch:
			m.flightMu.Lock()
			tok, err := m.lastToken[cacheKey], m.lastErr[cacheKey]
			m.flightMu.Unlock()
			return tok, err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	done := make(chan struct{})
	m.inFlight[cacheKey] = done
	m.flightMu.Unlock()

	defer func() {
		m.flightMu.Lock()
		delete(m.inFlight, cacheKey)
		close(done)
		m.flightMu.Unlock()
	}()

	tok, err := m.fetchTokenWithRetry(ctx, scopeKey)
	m.flightMu.Lock()
	m.lastToken[cacheKey] = tok
	m.lastErr[cacheKey] = err
	m.flightMu.Unlock()

	return tok, err
}

func (m *Module) fetchTokenWithRetry(ctx context.Context, scope string) (string, error) {
	var lastErr error

	for attempt := 0; attempt <= m.retry.MaxRetries; attempt++ {
		if attempt > 0 {
			delayMs := float64(m.retry.InitialDelayMs) * math.Pow(2, float64(attempt-1))
			jitter := delayMs * (0.8 + rand.Float64()*0.4)
			sleepDur := time.Duration(math.Min(jitter, float64(m.retry.MaxDelayMs))) * time.Millisecond

			select {
			case <-time.After(sleepDur):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		tok, expiresIn, retryable, err := m.fetchToken(ctx, scope)
		if err == nil {
			cacheKey := fmt.Sprintf("%s:%s", m.clientID, scope)
			m.cache.Set(cacheKey, tok, time.Duration(expiresIn)*time.Second, scope)
			return tok, nil
		}

		lastErr = err
		if !retryable {
			return "", err
		}
	}

	return "", fmt.Errorf("exceeded max token fetch retries: %w", lastErr)
}

func (m *Module) fetchToken(ctx context.Context, scope string) (token string, expiresIn int, retryable bool, err error) {
	tokenURL := fmt.Sprintf("%s/oauth/token", m.endpoint)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", m.clientID)
	data.Set("client_secret", m.clientSecret)
	if scope != "" {
		data.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", 0, true, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return "", 0, true, fmt.Errorf("server returned retryable status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, true, err
	}

	if resp.StatusCode != http.StatusOK {
		var errEnv ErrorEnvelope
		if jsonErr := json.Unmarshal(body, &errEnv); jsonErr == nil && errEnv.Error.Message != "" {
			return "", 0, false, fmt.Errorf("authentication error (%s): %s", errEnv.Error.Code, errEnv.Error.Message)
		}
		return "", 0, false, fmt.Errorf("oauth token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var oauthResp OAuthResponse
	if err := json.Unmarshal(body, &oauthResp); err != nil {
		return "", 0, false, err
	}

	if oauthResp.AccessToken == "" {
		return "", 0, false, errors.New("access_token not found in response")
	}

	exp := oauthResp.ExpiresIn
	if exp <= 0 {
		exp = 3600
	}

	return oauthResp.AccessToken, exp, false, nil
}
