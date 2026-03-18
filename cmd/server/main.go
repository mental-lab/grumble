package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/mental-lab/grumble/pkg/server"
)

func main() {
	var (
		grpcAddr string
		httpAddr string
		dbPath   string
		tlsCert  string
		tlsKey   string
	)

	cmd := &cobra.Command{
		Use:   "grumble-server",
		Short: "Grumble central server — aggregates scan results from all cluster agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			log, _ := zap.NewProduction()
			defer log.Sync()

			store, err := server.NewStore(dbPath)
			if err != nil {
				return err
			}

			srv := server.New(store, log)
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
					httpServer.Shutdown(context.Background())
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

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
