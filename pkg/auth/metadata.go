package auth

import (
	"context"
	"fmt"

	"google.golang.org/grpc/metadata"
)

// grpcMetadataFromContext is a small helper used by both agent and server
// packages to extract gRPC metadata from a context.
func grpcMetadataFromContext(ctx context.Context) (metadata.MD, bool) {
	return metadata.FromIncomingContext(ctx)
}

// AgentMetadata returns the gRPC metadata an agent should send on connect,
// including both the auth token and the cluster identifier.
func AgentMetadata(clusterID string) metadata.MD {
	return metadata.Pairs(
		"x-grumble-cluster-id", clusterID,
	)
}

// OutgoingContext attaches agent metadata to an outgoing gRPC context.
func OutgoingContext(ctx context.Context, clusterID string) (context.Context, error) {
	if clusterID == "" {
		return nil, fmt.Errorf("clusterID must not be empty")
	}
	return metadata.NewOutgoingContext(ctx, AgentMetadata(clusterID)), nil
}
