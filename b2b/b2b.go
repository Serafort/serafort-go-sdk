package b2b

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type UserContext struct {
	UserID      string                 `json:"user_id"`
	TenantID    string                 `json:"tenant_id"`
	Email       string                 `json:"email,omitempty"`
	Roles       []string               `json:"roles"`
	Permissions []string               `json:"permissions"`
	Claims      map[string]interface{} `json:"claims"`
}

type TokenValidationOptions struct {
	ExpectedIssuer     string
	ExpectedAudience   string
	ClockTolerance     time.Duration
	SkipSignatureCheck bool
}

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type Module struct {
	endpoint   string
	jwksClient *JwksClient
}

func NewModule(endpoint string) *Module {
	return &Module{
		endpoint:   strings.TrimRight(endpoint, "/"),
		jwksClient: NewJwksClient(endpoint),
	}
}

func (m *Module) SetJwksClient(jwks *JwksClient) {
	m.jwksClient = jwks
}

func (m *Module) ValidateToken(ctx context.Context, token string, opts ...TokenValidationOptions) (*UserContext, error) {
	var options TokenValidationOptions
	if len(opts) > 0 {
		options = opts[0]
	}
	if options.ClockTolerance == 0 {
		options.ClockTolerance = 60 * time.Second
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT: expected 3 dot-separated segments")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	now := time.Now()

	// 1. Expiration validation
	if expVal, exists := claims["exp"]; exists {
		if expFloat, ok := expVal.(float64); ok {
			expTime := time.Unix(int64(expFloat), 0)
			if now.After(expTime.Add(options.ClockTolerance)) {
				return nil, errors.New("token has expired")
			}
		}
	}

	// 2. Issuer validation
	expectedIss := options.ExpectedIssuer
	if expectedIss == "" {
		expectedIss = m.endpoint
	}
	if issVal, exists := claims["iss"]; exists && expectedIss != "" {
		if issStr, ok := issVal.(string); ok && issStr != expectedIss {
			return nil, fmt.Errorf("invalid token issuer: expected '%s', got '%s'", expectedIss, issStr)
		}
	}

	// 3. Signature verification
	if !options.SkipSignatureCheck {
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT signature: %w", err)
		}

		pubKey, err := m.jwksClient.GetPublicKey(ctx, header.Kid)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve public verification key: %w", err)
		}

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("unsupported key type: only RSA is currently supported")
		}

		signedData := []byte(parts[0] + "." + parts[1])
		hashed := sha256.Sum256(signedData)

		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
			return nil, fmt.Errorf("invalid token signature: %w", err)
		}
	}

	return m.mapClaimsToUser(claims), nil
}

func (m *Module) HasPermission(user *UserContext, required string) bool {
	if user == nil || len(user.Permissions) == 0 {
		return false
	}

	for _, perm := range user.Permissions {
		if perm == "*" || perm == required {
			return true
		}
		if strings.HasSuffix(perm, ":*") {
			prefix := strings.TrimSuffix(perm, ":*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

func (m *Module) HasRole(user *UserContext, role string) bool {
	if user == nil {
		return false
	}
	for _, r := range user.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (m *Module) GetLoginURL(tenantID, redirectURI string) string {
	u, _ := url.Parse(fmt.Sprintf("%s/api/auth/sso/login", m.endpoint))
	q := u.Query()
	q.Set("tenant_id", tenantID)
	q.Set("redirect_uri", redirectURI)
	u.RawQuery = q.Encode()
	return u.String()
}

func (m *Module) mapClaimsToUser(claims map[string]interface{}) *UserContext {
	user := &UserContext{
		Claims: claims,
	}

	if sub, ok := claims["sub"].(string); ok {
		user.UserID = sub
	} else if id, ok := claims["id"].(string); ok {
		user.UserID = id
	}

	if tid, ok := claims["tenant_id"].(string); ok {
		user.TenantID = tid
	} else if orgID, ok := claims["org_id"].(string); ok {
		user.TenantID = orgID
	}

	if email, ok := claims["email"].(string); ok {
		user.Email = email
	}

	if rolesVal, ok := claims["roles"].([]interface{}); ok {
		for _, r := range rolesVal {
			if rStr, ok := r.(string); ok {
				user.Roles = append(user.Roles, rStr)
			}
		}
	}

	if permsVal, ok := claims["permissions"].([]interface{}); ok {
		for _, p := range permsVal {
			if pStr, ok := p.(string); ok {
				user.Permissions = append(user.Permissions, pStr)
			}
		}
	}

	return user
}
