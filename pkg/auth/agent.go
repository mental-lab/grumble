// Package auth handles OIDC-based authentication between the grumble
// agent and server using Kubernetes Service Account tokens.
//
// The agent reads its auto-mounted ServiceAccount JWT and attaches it
// to every gRPC call. Tokens are short-lived (~1hr) and auto-rotated
// by Kubernetes — no cert management required.
package auth

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	// Standard Kubernetes ServiceAccount token path
	defaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// gRPC metadata key carrying the bearer token
	authorizationHeader = "authorization"

	// Refresh the token 5 minutes before it expires
	tokenRefreshBuffer = 5 * time.Minute
)

// TokenSource reads and refreshes a Kubernetes ServiceAccount JWT.
// It implements credentials.PerRPCCredentials so it can be used
// directly as a gRPC dial option.
type TokenSource struct {
	tokenPath string

	mu          sync.RWMutex
	cachedToken string
	readAt      time.Time
	ttl         time.Duration
}

// NewTokenSource creates a TokenSource that reads from the given path.
// Pass an empty string to use the default in-cluster path.
func NewTokenSource(tokenPath string) *TokenSource {
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	return &TokenSource{
		tokenPath: tokenPath,
		ttl:       55 * time.Minute, // K8s default token lifetime is 1hr
	}
}

// GetRequestMetadata returns the Authorization header for each gRPC call.
// It refreshes the token when it is close to expiry.
func (t *TokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := t.token()
	if err != nil {
		return nil, fmt.Errorf("reading service account token: %w", err)
	}
	return map[string]string{
		authorizationHeader: "Bearer " + token,
	}, nil
}

// RequireTransportSecurity returns true — always use with TLS in production.
func (t *TokenSource) RequireTransportSecurity() bool {
	return true
}

// Verify implements credentials.PerRPCCredentials
var _ credentials.PerRPCCredentials = (*TokenSource)(nil)

// IncomingToken extracts the bearer token from incoming gRPC metadata.
func IncomingToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata in context")
	}
	vals := md.Get(authorizationHeader)
	if len(vals) == 0 {
		return "", fmt.Errorf("missing authorization header")
	}
	token := vals[0]
	if len(token) < 8 || token[:7] != "Bearer " {
		return "", fmt.Errorf("authorization header must be 'Bearer <token>'")
	}
	return token[7:], nil
}

func (t *TokenSource) token() (string, error) {
	t.mu.RLock()
	if t.cachedToken != "" && time.Since(t.readAt) < t.ttl-tokenRefreshBuffer {
		tok := t.cachedToken
		t.mu.RUnlock()
		return tok, nil
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()

	raw, err := os.ReadFile(t.tokenPath)
	if err != nil {
		return "", fmt.Errorf("reading token from %s: %w", t.tokenPath, err)
	}
	t.cachedToken = string(raw)
	t.readAt = time.Now()
	return t.cachedToken, nil
}
