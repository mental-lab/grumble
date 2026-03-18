package agent

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/mental-lab/grumble/pkg/auth"
	proto "github.com/mental-lab/grumble/pkg/proto"
	"github.com/mental-lab/grumble/pkg/tlsconfig"
)

const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 2 * time.Minute
	backoffMult    = 1.6
	jitterFraction = 0.2
)

// Agent is the in-cluster component. It:
//   - watches pods via the K8s informer
//   - scans new/changed images with Grype
//   - streams results to the Grumble server over gRPC
//
// The agent always initiates the outbound connection — no inbound
// ports are required, making it firewall/NAT friendly.
type Agent struct {
	cfg     Config
	watcher *Watcher
	scanner *Scanner
	log     *zap.Logger
}

type Config struct {
	AgentID    string
	ClusterID  string
	ServerAddr string // grumble-server address e.g. grumble.example.com:9090
	GrypeDBDir string

	// TLSCAFile is the CA cert used to verify the server's TLS certificate.
	// Leave empty to use system CAs (e.g. for publicly trusted certs).
	TLSCAFile string

	// SATokenPath is the path to the Kubernetes ServiceAccount token used for
	// OIDC authentication. Defaults to the standard in-cluster path.
	SATokenPath string

	// Dev disables TLS and OIDC authentication. For local testing only.
	Dev bool
}

func New(cfg Config, watcher *Watcher, scanner *Scanner, log *zap.Logger) *Agent {
	return &Agent{cfg: cfg, watcher: watcher, scanner: scanner, log: log}
}

func (a *Agent) Run(ctx context.Context) error {
	// Run watcher in background
	go func() {
		if err := a.watcher.Run(ctx); err != nil && ctx.Err() == nil {
			a.log.Error("watcher exited", zap.Error(err))
		}
	}()

	// Connect to server with exponential backoff retry
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := a.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			backoff := calcBackoff(attempt)
			a.log.Warn("connection lost, retrying",
				zap.Error(err),
				zap.Duration("backoff", backoff),
				zap.Int("attempt", attempt+1))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (a *Agent) connect(ctx context.Context) error {
	dialOpts := []grpc.DialOption{grpc.WithBlock()}

	// Transport encryption — verify server cert if CA provided, else use system CAs
	if a.cfg.TLSCAFile != "" {
		creds, err := tlsconfig.AgentCredentials(a.cfg.TLSCAFile)
		if err != nil {
			return fmt.Errorf("building TLS credentials: %w", err)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
		a.log.Info("TLS enabled with custom CA")
	} else {
		a.log.Warn("TLS not configured — using insecure transport (dev only)")
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Authentication via Kubernetes ServiceAccount OIDC token (skipped in dev mode)
	if !a.cfg.Dev {
		tokenSource := auth.NewTokenSource(a.cfg.SATokenPath)
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(tokenSource))
		a.log.Info("OIDC ServiceAccount token auth enabled")
	} else {
		a.log.Warn("OIDC auth disabled (dev mode)")
	}

	conn, err := grpc.DialContext(ctx, a.cfg.ServerAddr, dialOpts...)
	if err != nil {
		return fmt.Errorf("dialing server: %w", err)
	}
	defer conn.Close()

	// Attach cluster-id metadata so the server can select the right OIDC verifier
	connCtx, err := auth.OutgoingContext(ctx, a.cfg.ClusterID)
	if err != nil {
		return fmt.Errorf("building outgoing context: %w", err)
	}

	client := proto.NewGrumbleServerClient(conn)
	stream, err := client.Connect(connCtx)
	if err != nil {
		return fmt.Errorf("opening stream: %w", err)
	}

	a.log.Info("connected to grumble server",
		zap.String("server", a.cfg.ServerAddr),
		zap.String("cluster", a.cfg.ClusterID))

	// Register on connect
	if err := stream.Send(&proto.AgentMessage{
		AgentId:   a.cfg.AgentID,
		ClusterId: a.cfg.ClusterID,
		Payload: &proto.AgentMessage_Register{
			Register: &proto.Registration{
				ClusterId:   a.cfg.ClusterID,
				AgentVersion: "0.1.0",
			},
		},
	}); err != nil {
		return fmt.Errorf("sending registration: %w", err)
	}

	// Process pod events and scan images
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-a.watcher.Events():
			if event.Type == "DELETE" {
				continue
			}
			for _, c := range event.Pod.Spec.Containers {
				go a.scanAndSend(ctx, stream, c.Image)
			}
		}
	}
}

func (a *Agent) scanAndSend(ctx context.Context, stream proto.GrumbleServer_ConnectClient, image string) {
	scanID := fmt.Sprintf("%s-%d", a.cfg.ClusterID, time.Now().UnixNano())
	result, err := a.scanner.Scan(ctx, scanID, image)
	if err != nil {
		a.log.Error("scan failed", zap.String("image", image), zap.Error(err))
		return
	}

	if err := stream.Send(&proto.AgentMessage{
		AgentId:   a.cfg.AgentID,
		ClusterId: a.cfg.ClusterID,
		Payload: &proto.AgentMessage_ScanResult{
			ScanResult: result,
		},
	}); err != nil {
		a.log.Error("failed to send scan result", zap.Error(err))
	}
}

func calcBackoff(attempt int) time.Duration {
	b := float64(initialBackoff) * math.Pow(backoffMult, float64(attempt))
	if b > float64(maxBackoff) {
		b = float64(maxBackoff)
	}
	jitter := b * jitterFraction * (rand.Float64()*2 - 1)
	return time.Duration(b + jitter)
}
