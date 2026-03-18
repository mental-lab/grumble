package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClusterConfig tells the validator how to verify tokens from a specific cluster.
type ClusterConfig struct {
	// IssuerURL is the OIDC issuer for this cluster's API server.
	// e.g. "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
	// For in-cluster: "https://kubernetes.default.svc"
	IssuerURL string

	// Audience is the expected token audience.
	// Defaults to "https://kubernetes.default.svc.cluster.local" if empty.
	Audience string
}

// Validator validates Kubernetes ServiceAccount JWTs from agents.
// Each cluster has its own OIDC issuer so we maintain a verifier per cluster.
type Validator struct {
	clusters map[string]*oidc.IDTokenVerifier // clusterID → verifier
	log      *zap.Logger
}

// KubernetesClaims are the standard claims in a K8s SA token
type KubernetesClaims struct {
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// AgentIdentity is the verified identity extracted from a valid token
type AgentIdentity struct {
	ClusterID      string
	Namespace      string
	ServiceAccount string
	Subject        string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

// NewValidator creates a Validator for the given clusters.
// Call this once at server startup with all registered clusters.
func NewValidator(ctx context.Context, clusters map[string]ClusterConfig, log *zap.Logger) (*Validator, error) {
	v := &Validator{
		clusters: make(map[string]*oidc.IDTokenVerifier),
		log:      log,
	}

	for clusterID, cfg := range clusters {
		audience := cfg.Audience
		if audience == "" {
			audience = "https://kubernetes.default.svc.cluster.local"
		}

		provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("creating OIDC provider for cluster %s (%s): %w",
				clusterID, cfg.IssuerURL, err)
		}

		verifier := provider.Verifier(&oidc.Config{
			ClientID: audience,
		})

		v.clusters[clusterID] = verifier
		log.Info("registered OIDC verifier",
			zap.String("cluster", clusterID),
			zap.String("issuer", cfg.IssuerURL))
	}

	return v, nil
}

// Verify validates a raw JWT and returns the agent's identity.
// The clusterID claim is extracted from the token subject to select
// the correct verifier.
func (v *Validator) Verify(ctx context.Context, clusterID, rawToken string) (*AgentIdentity, error) {
	verifier, ok := v.clusters[clusterID]
	if !ok {
		return nil, fmt.Errorf("unknown cluster: %s", clusterID)
	}

	idToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	var claims KubernetesClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extracting claims: %w", err)
	}

	return &AgentIdentity{
		ClusterID:      clusterID,
		Namespace:      claims.Kubernetes.Namespace,
		ServiceAccount: claims.Kubernetes.ServiceAccount.Name,
		Subject:        idToken.Subject,
		IssuedAt:       idToken.IssuedAt,
		ExpiresAt:      idToken.Expiry,
	}, nil
}

// UnaryInterceptor returns a gRPC server interceptor that validates
// the bearer token on every unary RPC call.
func (v *Validator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if _, err := v.authenticate(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC server interceptor that validates
// the bearer token on every streaming RPC (used by Connect).
func (v *Validator) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		identity, err := v.authenticate(ss.Context())
		if err != nil {
			return err
		}
		v.log.Info("agent authenticated",
			zap.String("cluster", identity.ClusterID),
			zap.String("serviceAccount", identity.ServiceAccount),
			zap.String("namespace", identity.Namespace))
		return handler(srv, ss)
	}
}

func (v *Validator) authenticate(ctx context.Context) (*AgentIdentity, error) {
	rawToken, err := IncomingToken(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing token: %v", err)
	}

	// Extract clusterID from metadata (sent alongside the token)
	clusterID, err := clusterIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing cluster-id: %v", err)
	}

	identity, err := v.Verify(ctx, clusterID, rawToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	return identity, nil
}

func clusterIDFromContext(ctx context.Context) (string, error) {
	md, ok := grpcMetadataFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata")
	}
	vals := md["x-grumble-cluster-id"]
	if len(vals) == 0 {
		return "", fmt.Errorf("x-grumble-cluster-id header missing")
	}
	return vals[0], nil
}
