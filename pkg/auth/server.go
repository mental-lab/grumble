package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TokenStore looks up a token hash and returns the associated cluster ID.
// Implemented by the server's SQLite store.
type TokenStore interface {
	LookupToken(ctx context.Context, tokenHash string) (clusterID string, err error)
}

// AgentIdentity is the verified identity of a connected agent.
type AgentIdentity struct {
	ClusterID string
	TokenHash string
	VerifiedAt time.Time
}

// Validator validates agent bearer tokens using a token store.
type Validator struct {
	store TokenStore
	log   *zap.Logger
}

// NewValidator creates a Validator backed by the given store.
func NewValidator(store TokenStore, log *zap.Logger) *Validator {
	return &Validator{store: store, log: log}
}

// GenerateToken returns a new random agent token and its SHA-256 hash.
// Store only the hash; give the token to the cluster admin once — it cannot
// be recovered from the stored hash.
func GenerateToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating token: %w", err)
	}
	token = "grumble_" + base64.RawURLEncoding.EncodeToString(b)
	hash = HashToken(token)
	return token, hash, nil
}

// HashToken returns the hex-encoded SHA-256 of a token.
// Tokens are 256 bits of entropy so no salt is needed.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Verify validates a raw bearer token and returns the agent's identity.
func (v *Validator) Verify(ctx context.Context, rawToken string) (*AgentIdentity, error) {
	hash := HashToken(rawToken)
	clusterID, err := v.store.LookupToken(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}
	return &AgentIdentity{
		ClusterID:  clusterID,
		TokenHash:  hash,
		VerifiedAt: time.Now(),
	}, nil
}

// UnaryInterceptor returns a gRPC server interceptor that validates the bearer
// token on every unary RPC call.
func (v *Validator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if _, err := v.authenticate(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC server interceptor that validates the bearer
// token on every streaming RPC.
func (v *Validator) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		identity, err := v.authenticate(ss.Context())
		if err != nil {
			return err
		}
		v.log.Info("agent authenticated", zap.String("cluster", identity.ClusterID))
		return handler(srv, ss)
	}
}

func (v *Validator) authenticate(ctx context.Context) (*AgentIdentity, error) {
	rawToken, err := IncomingToken(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing token: %v", err)
	}
	identity, err := v.Verify(ctx, rawToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}
	return identity, nil
}
