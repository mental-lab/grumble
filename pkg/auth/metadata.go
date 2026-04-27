package auth

import "context"

// OutgoingContext returns ctx unchanged. With token-based auth the bearer token
// is attached automatically via TokenSource.GetRequestMetadata — no extra
// metadata headers are needed.
func OutgoingContext(ctx context.Context, _ string) (context.Context, error) {
	return ctx, nil
}
