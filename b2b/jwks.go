package b2b

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JwksClient struct {
	jwksURL    string
	httpClient *http.Client
	mu         sync.RWMutex
	keys       map[string]crypto.PublicKey
	fetchedAt  time.Time
	cacheTTL   time.Duration
}

func NewJwksClient(endpoint string) *JwksClient {
	return &JwksClient{
		jwksURL:    fmt.Sprintf("%s/.well-known/jwks.json", strings.TrimRight(endpoint, "/")),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]crypto.PublicKey),
		cacheTTL:   1 * time.Hour,
	}
}

func (j *JwksClient) SetHTTPClient(client *http.Client) {
	j.httpClient = client
}

func (j *JwksClient) GetPublicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	j.mu.RLock()
	if len(j.keys) > 0 && time.Since(j.fetchedAt) < j.cacheTTL {
		if key, exists := j.keys[kid]; exists {
			j.mu.RUnlock()
			return key, nil
		}
		// If kid is empty and only 1 key exists
		if kid == "" && len(j.keys) == 1 {
			for _, k := range j.keys {
				j.mu.RUnlock()
				return k, nil
			}
		}
	}
	j.mu.RUnlock()

	if err := j.refresh(ctx); err != nil {
		return nil, err
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	if key, exists := j.keys[kid]; exists {
		return key, nil
	}
	if kid == "" && len(j.keys) > 0 {
		for _, k := range j.keys {
			return k, nil
		}
	}

	return nil, fmt.Errorf("public key with kid '%s' not found in JWKS", kid)
}

func (j *JwksClient) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", j.jwksURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS from %s: %w", j.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned HTTP status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	newKeys := make(map[string]crypto.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty == "RSA" && k.N != "" && k.E != "" {
			pubKey, err := parseRSAPublicKey(k.N, k.E)
			if err == nil {
				newKeys[k.Kid] = pubKey
			}
		}
	}

	j.mu.Lock()
	j.keys = newKeys
	j.fetchedAt = time.Now()
	j.mu.Unlock()

	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
