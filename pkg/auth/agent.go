// Package auth handles token-based authentication between the grumble
// agent and server.
//
// The agent reads a pre-shared token from a Kubernetes Secret mounted
// at a well-known path and attaches it to every gRPC call as a bearer token.
// Tokens are registered server-side via `grumble-server register-cluster`.
package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	// Default path where the Helm chart mounts the agent token Secret.
	defaultTokenPath = "/var/run/secrets/grumble/token"

	// gRPC metadata key carrying the bearer token.
	authorizationHeader = "authorization"

	// Re-read the token file this often to pick up manual rotations.
	tokenCacheTTL = 5 * time.Minute
)

// TokenSource reads an agent token from a Kubernetes Secret and attaches it
// to gRPC calls as a bearer token. It implements credentials.PerRPCCredentials.
type TokenSource struct {
	tokenPath string

	mu          sync.RWMutex
	cachedToken string
	readAt      time.Time
}

// NewTokenSource creates a TokenSource that reads from the given path.
// Pass an empty string to use the default in-cluster secret mount path.
func NewTokenSource(tokenPath string) *TokenSource {
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	return &TokenSource{tokenPath: tokenPath}
}

// GetRequestMetadata returns the Authorization header for each gRPC call.
func (t *TokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := t.token()
	if err != nil {
		return nil, fmt.Errorf("reading agent token: %w", err)
	}
	return map[string]string{
		authorizationHeader: "Bearer " + token,
	}, nil
}

// RequireTransportSecurity returns true — always use with TLS in production.
func (t *TokenSource) RequireTransportSecurity() bool {
	return true
}

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
	if t.cachedToken != "" && time.Since(t.readAt) < tokenCacheTTL {
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
	t.cachedToken = strings.TrimSpace(string(raw))
	t.readAt = time.Now()
	return t.cachedToken, nil
}
