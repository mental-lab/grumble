package auth_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/mental-lab/grumble/pkg/auth"
)

const testClusterID = "test-cluster"

// memTokenStore is an in-memory TokenStore for tests.
type memTokenStore struct {
	tokens map[string]string // hash → clusterID
}

func (m *memTokenStore) LookupToken(_ context.Context, hash string) (string, error) {
	id, ok := m.tokens[hash]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return id, nil
}

func newTestValidator(t *testing.T) (*auth.Validator, string) {
	t.Helper()
	token, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	store := &memTokenStore{tokens: map[string]string{hash: testClusterID}}
	return auth.NewValidator(store, zap.NewNop()), token
}

func TestVerify_ValidToken(t *testing.T) {
	v, token := newTestValidator(t)

	identity, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if identity.ClusterID != testClusterID {
		t.Errorf("ClusterID = %q, want %q", identity.ClusterID, testClusterID)
	}
	if identity.VerifiedAt.IsZero() {
		t.Error("VerifiedAt is zero")
	}
}

func TestVerify_UnknownToken(t *testing.T) {
	v, _ := newTestValidator(t)

	_, err := v.Verify(context.Background(), "grumble_notregistered")
	if err == nil {
		t.Fatal("expected error for unknown token, got nil")
	}
}

func TestVerify_EmptyToken(t *testing.T) {
	v, _ := newTestValidator(t)

	_, err := v.Verify(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestGenerateToken_Format(t *testing.T) {
	token, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if len(token) < 10 || token[:8] != "grumble_" {
		t.Errorf("token %q does not start with grumble_", token)
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64 (hex SHA-256)", len(hash))
	}
	if auth.HashToken(token) != hash {
		t.Error("HashToken(token) != hash returned by GenerateToken")
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	tok1, _, _ := auth.GenerateToken()
	tok2, _, _ := auth.GenerateToken()
	if tok1 == tok2 {
		t.Error("two generated tokens are identical")
	}
}

func TestTokenSource_ReadsToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("grumble_testtoken\n"), 0600); err != nil {
		t.Fatal(err)
	}

	src := auth.NewTokenSource(path)
	md, err := src.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	if md["authorization"] != "Bearer grumble_testtoken" {
		t.Errorf("authorization = %q, want %q", md["authorization"], "Bearer grumble_testtoken")
	}
}
