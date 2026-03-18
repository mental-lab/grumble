// Package tlsconfig provides helpers for building TLS credentials
// for the gRPC connection between grumble-agent and grumble-server.
//
// Authentication is handled by OIDC ServiceAccount tokens (see pkg/auth).
// TLS here provides transport encryption only — no client certificates needed.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// ServerCredentials returns gRPC transport credentials for the server.
// Agents authenticate via OIDC tokens — no client cert required.
func ServerCredentials(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server cert/key: %w", err)
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // OIDC tokens handle auth
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// AgentCredentials returns gRPC transport credentials for the agent.
// Verifies the server cert against the provided CA.
// Agent identity is proven via OIDC token, not a client cert.
func AgentCredentials(caFile string) (credentials.TransportCredentials, error) {
	pool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}), nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("failed to parse CA cert from %s", caFile)
	}
	return pool, nil
}
