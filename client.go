package serafort

import (
	"context"

	"github.com/Serafort/serafort-go-sdk/b2b"
	"github.com/Serafort/serafort-go-sdk/m2m"
)

type Config struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	PrivateKey   string
}

type Client struct {
	Config Config
	M2M    *m2m.Module
	B2B    *b2b.Module
}

func NewClient(cfg Config) *Client {
	return &Client{
		Config: cfg,
		M2M:    m2m.NewModule(cfg.Endpoint, cfg.ClientID, cfg.ClientSecret, cfg.PrivateKey),
		B2B:    b2b.NewModule(cfg.Endpoint),
	}
}

// GetAccessToken retrieves an M2M access token from cache or transparently fetches a new one.
func (c *Client) GetAccessToken(ctx context.Context, scopes []string) (string, error) {
	return c.M2M.GetAccessToken(ctx, scopes)
}

// ValidateToken validates a JWT token locally and decodes its UserContext.
func (c *Client) ValidateToken(ctx context.Context, token string, opts ...b2b.TokenValidationOptions) (*b2b.UserContext, error) {
	return c.B2B.ValidateToken(ctx, token, opts...)
}

// HasPermission checks if the user possesses a specific permission (supports wildcards).
func (c *Client) HasPermission(user *b2b.UserContext, required string) bool {
	return c.B2B.HasPermission(user, required)
}

// HasRole checks if the user possesses a specific role.
func (c *Client) HasRole(user *b2b.UserContext, role string) bool {
	return c.B2B.HasRole(user, role)
}
