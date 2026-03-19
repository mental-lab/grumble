package auth_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"

	"github.com/mental-lab/grumble/pkg/auth"
	"github.com/mental-lab/grumble/pkg/auth/testoidc"
)

const (
	testCluster  = "test-cluster"
	testAudience = "https://kubernetes.default.svc.cluster.local"
)

// newValidator is a helper that creates a Validator backed by the mock provider.
func newValidator(t *testing.T, provider *testoidc.Provider) *auth.Validator {
	t.Helper()
	v, err := auth.NewValidator(context.Background(), map[string]auth.ClusterConfig{
		testCluster: {
			IssuerURL: provider.IssuerURL(),
			Audience:  testAudience,
		},
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func TestVerify_ValidToken(t *testing.T) {
	provider := testoidc.New(t)
	v := newValidator(t, provider)

	token := provider.Token("default", "grumble-agent", testAudience, time.Now().Add(time.Hour))

	identity, err := v.Verify(context.Background(), testCluster, token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if identity.ClusterID != testCluster {
		t.Errorf("ClusterID = %q, want %q", identity.ClusterID, testCluster)
	}
	if identity.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", identity.Namespace, "default")
	}
	if identity.ServiceAccount != "grumble-agent" {
		t.Errorf("ServiceAccount = %q, want %q", identity.ServiceAccount, "grumble-agent")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	provider := testoidc.New(t)
	v := newValidator(t, provider)

	// Token expired 1 hour ago
	token := provider.Token("default", "grumble-agent", testAudience, time.Now().Add(-time.Hour))

	_, err := v.Verify(context.Background(), testCluster, token)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestVerify_UnknownCluster(t *testing.T) {
	provider := testoidc.New(t)
	v := newValidator(t, provider)

	token := provider.Token("default", "grumble-agent", testAudience, time.Now().Add(time.Hour))

	_, err := v.Verify(context.Background(), "unknown-cluster", token)
	if err == nil {
		t.Fatal("expected error for unknown cluster, got nil")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	provider := testoidc.New(t)
	v := newValidator(t, provider)

	// Token minted for a different audience
	token := provider.Token("default", "grumble-agent", "https://other.example.com", time.Now().Add(time.Hour))

	_, err := v.Verify(context.Background(), testCluster, token)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

func TestAuthenticate_MissingToken(t *testing.T) {
	provider := testoidc.New(t)
	v := newValidator(t, provider)

	// Context with cluster-id metadata but no Authorization header
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-grumble-cluster-id", testCluster,
	))

	_, err := v.Verify(ctx, testCluster, "")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}
