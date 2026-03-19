package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/mental-lab/grumble/pkg/auth"
	"github.com/mental-lab/grumble/pkg/server"
)

func main() {
	var (
		grpcAddr string
		httpAddr string
		dbPath   string
		tlsCert  string
		tlsKey   string
		devMode  bool
		clusters []string // repeated --cluster id=issuer_url flags
	)

	cmd := &cobra.Command{
		Use:   "grumble-server",
		Short: "Grumble central server — aggregates scan results from all cluster agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			log, _ := zap.NewProduction()
			defer log.Sync() //nolint:errcheck

			store, err := server.NewStore(dbPath)
			if err != nil {
				return err
			}

			var validator *auth.Validator
			if devMode {
				log.Warn("--dev mode enabled: OIDC auth disabled, all agents accepted")
			} else {
				clusterConfigs, err := parseClusters(clusters)
				if err != nil {
					return fmt.Errorf("invalid --cluster flag: %w", err)
				}
				if len(clusterConfigs) == 0 {
					return fmt.Errorf("at least one --cluster flag is required in production mode (or use --dev)")
				}
				validator, err = auth.NewValidator(cmd.Context(), clusterConfigs, log)
				if err != nil {
					return fmt.Errorf("initializing OIDC validator: %w", err)
				}
			}

			srv := server.New(store, validator, log)
			api := server.NewAPI(store, log)

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			g, ctx := errgroup.WithContext(ctx)

			// gRPC server — agents connect here
			var tlsCfg *server.TLSConfig
			if tlsCert != "" {
				tlsCfg = &server.TLSConfig{
					CertFile: tlsCert,
					KeyFile:  tlsKey,
				}
			}
			g.Go(func() error {
				log.Info("starting gRPC server", zap.String("addr", grpcAddr))
				return srv.Run(grpcAddr, tlsCfg)
			})

			// HTTP API — Grafana queries here
			g.Go(func() error {
				log.Info("starting HTTP API", zap.String("addr", httpAddr))
				httpServer := &http.Server{Addr: httpAddr, Handler: api.Handler()}
				go func() {
					<-ctx.Done()
					httpServer.Shutdown(context.Background()) //nolint:errcheck
				}()
				return httpServer.ListenAndServe()
			})

			return g.Wait()
		},
	}

	cmd.Flags().StringVar(&grpcAddr, "grpc-addr", ":9090", "gRPC listen address (agents connect here)")
	cmd.Flags().StringVar(&httpAddr, "http-addr", ":8080", "HTTP API listen address (Grafana connects here)")
	cmd.Flags().StringVar(&dbPath, "db", "/data/grumble.db", "SQLite database path")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Server TLS certificate file (enables TLS)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Server TLS key file")
	cmd.Flags().BoolVar(&devMode, "dev", false, "Disable OIDC auth for local development")
	cmd.Flags().StringArrayVar(&clusters, "cluster", nil,
		"Register a cluster for OIDC auth: --cluster id=https://issuer-url (repeatable)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// parseClusters parses --cluster id=issuer_url flags into a ClusterConfig map.
func parseClusters(raw []string) (map[string]auth.ClusterConfig, error) {
	configs := make(map[string]auth.ClusterConfig, len(raw))
	for _, s := range raw {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("%q: expected format id=issuer_url", s)
		}
		configs[parts[0]] = auth.ClusterConfig{IssuerURL: parts[1]}
	}
	return configs, nil
}
