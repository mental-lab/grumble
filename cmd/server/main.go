package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/mental-lab/grumble/pkg/auth"
	"github.com/mental-lab/grumble/pkg/server"
)

func main() {
	root := &cobra.Command{
		Use:   "grumble-server",
		Short: "Grumble central server — aggregates scan results from all cluster agents",
	}
	root.AddCommand(serveCmd(), registerCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	var (
		grpcAddr string
		httpAddr string
		dbPath   string
		tlsCert  string
		tlsKey   string
		devMode  bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gRPC and HTTP servers",
		// Keep bare invocation working for backwards compatibility with existing deployments.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log, _ := zap.NewProduction()
			defer log.Sync() //nolint:errcheck

			store, err := server.NewStore(dbPath)
			if err != nil {
				return err
			}

			var validator *auth.Validator
			if devMode {
				log.Warn("--dev mode enabled: token auth disabled, all agents accepted")
			} else {
				validator = auth.NewValidator(store, log)
			}

			srv := server.New(store, validator, log)
			api := server.NewAPI(store, log)

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			g, ctx := errgroup.WithContext(ctx)

			var tlsCfg *server.TLSConfig
			if tlsCert != "" {
				tlsCfg = &server.TLSConfig{CertFile: tlsCert, KeyFile: tlsKey}
			}
			g.Go(func() error {
				log.Info("starting gRPC server", zap.String("addr", grpcAddr))
				return srv.Run(grpcAddr, tlsCfg)
			})

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

	cmd.Flags().StringVar(&grpcAddr, "grpc-addr", ":9090", "gRPC listen address")
	cmd.Flags().StringVar(&httpAddr, "http-addr", ":8080", "HTTP API listen address")
	cmd.Flags().StringVar(&dbPath, "db", "/data/grumble.db", "SQLite database path")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Server TLS certificate file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Server TLS key file")
	cmd.Flags().BoolVar(&devMode, "dev", false, "Disable token auth for local development")
	return cmd
}

func registerCmd() *cobra.Command {
	var (
		dbPath    string
		clusterID string
	)

	cmd := &cobra.Command{
		Use:   "register-cluster",
		Short: "Register a cluster and generate an agent token",
		Long: `Generates a random agent token for a cluster and stores its hash in the database.
Print the token once — it cannot be recovered. Store it in a Kubernetes Secret:

  kubectl create secret generic grumble-token \
    --from-literal=token=<printed-token>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := server.NewStore(dbPath)
			if err != nil {
				return err
			}

			token, hash, err := auth.GenerateToken()
			if err != nil {
				return fmt.Errorf("generating token: %w", err)
			}

			if err := store.RegisterToken(clusterID, hash); err != nil {
				return fmt.Errorf("storing token: %w", err)
			}

			fmt.Printf("Cluster: %s\nToken:   %s\n\nStore this token in a Kubernetes Secret:\n  kubectl create secret generic grumble-token --from-literal=token=%s\n", clusterID, token, token)
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "/data/grumble.db", "SQLite database path")
	cmd.Flags().StringVar(&clusterID, "name", "", "Cluster name (required)")
	if err := cmd.MarkFlagRequired("name"); err != nil {
		panic(err)
	}
	return cmd
}
