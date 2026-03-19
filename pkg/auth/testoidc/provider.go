// Package testoidc provides a minimal mock OIDC provider for use in tests.
// It spins up an httptest.Server that serves a discovery document and JWKS
// endpoint, and can mint RS256-signed JWTs for use in auth tests.
package testoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const keyID = "test-key-1"

// Provider is a minimal in-process OIDC provider for use in tests.
type Provider struct {
	server  *httptest.Server
	privKey *rsa.PrivateKey
}

// New creates and starts a mock OIDC provider.
// It registers a t.Cleanup to close the server automatically.
func New(t *testing.T) *Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("testoidc: generating RSA key: %v", err)
	}

	p := &Provider{privKey: key}

	mux := http.NewServeMux()
	// httptest.NewServer starts immediately; handlers are registered below
	// and resolved at request time, so p.server.URL is available inside them.
	p.server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/keys", p.handleKeys)

	t.Cleanup(p.server.Close)
	return p
}

// IssuerURL returns the URL to pass as the OIDC issuer for this provider.
func (p *Provider) IssuerURL() string {
	return p.server.URL
}

// Token mints a signed RS256 JWT that the mock provider will accept.
// audience should match the ClusterConfig.Audience passed to NewValidator.
func (p *Provider) Token(namespace, serviceAccount, audience string, exp time.Time) string {
	header := mustB64J(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": keyID,
	})
	payload := mustB64J(map[string]any{
		"iss": p.server.URL,
		"sub": "system:serviceaccount:" + namespace + ":" + serviceAccount,
		"aud": []string{audience},
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
		"kubernetes.io": map[string]any{
			"namespace": namespace,
			"serviceaccount": map[string]any{
				"name": serviceAccount,
				"uid":  "test-uid",
			},
		},
	})

	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.privKey, crypto.SHA256, digest[:])
	if err != nil {
		panic("testoidc: signing JWT: " + err.Error())
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":   p.server.URL,
		"jwks_uri": p.server.URL + "/keys",
	})
}

func (p *Provider) handleKeys(w http.ResponseWriter, _ *http.Request) {
	pub := &p.privKey.PublicKey
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": keyID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func mustB64J(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
