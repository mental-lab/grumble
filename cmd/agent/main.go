package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/mental-lab/grumble/pkg/agent"
)

func main() {
	var (
		serverAddr   string
		clusterID    string
		agentID      string
		grypeDBDir   string
		kubeconfig   string
		tlsCA        string
		saTokenPath  string
		dev          bool
		scanInterval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "grumble-agent",
		Short: "Grumble in-cluster agent — watches pods and scans images with Grype",
		RunE: func(cmd *cobra.Command, args []string) error {
			log, _ := zap.NewProduction()
			defer log.Sync()

			cfg, err := buildKubeConfig(kubeconfig)
			if err != nil {
				return err
			}

			client, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				return err
			}

			scanner, err := agent.NewScanner(clusterID, grypeDBDir, log)
			if err != nil {
				return err
			}

			watcher := agent.NewWatcher(client, log)

			a := agent.New(agent.Config{
				AgentID:      agentID,
				ClusterID:    clusterID,
				ServerAddr:   serverAddr,
				GrypeDBDir:   grypeDBDir,
				TLSCAFile:    tlsCA,
				SATokenPath:  saTokenPath,
				Dev:          dev,
				ScanInterval: scanInterval,
			}, watcher, scanner, log)

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			log.Info("starting grumble agent",
				zap.String("cluster", clusterID),
				zap.String("server", serverAddr))

			return a.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&serverAddr, "server", "grumble-server:9090", "Grumble server address")
	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "Unique cluster identifier (required)")
	cmd.Flags().StringVar(&agentID, "agent-id", "", "Unique agent identifier")
	cmd.Flags().StringVar(&grypeDBDir, "grype-db-dir", "/tmp/grype-db", "Directory for Grype vulnerability DB")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to in-cluster config)")
	cmd.Flags().StringVar(&tlsCA, "tls-ca", "", "CA cert to verify server TLS certificate (uses system CAs if omitted)")
	cmd.Flags().StringVar(&saTokenPath, "sa-token-path", "", "Path to ServiceAccount token for OIDC auth (uses default in-cluster path if omitted)")
	cmd.Flags().BoolVar(&dev, "dev", false, "Disable TLS and OIDC auth (local testing only)")
	cmd.Flags().DurationVar(&scanInterval, "scan-interval", 24*time.Hour, "How often to re-scan all running images (0 to disable)")
	cmd.MarkFlagRequired("cluster-id")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildKubeConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
