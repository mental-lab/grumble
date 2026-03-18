package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/mental-lab/grumble/pkg/agent"
)

func main() {
	var (
		serverAddr string
		clusterID  string
		agentID    string
		grypeDBDir string
		kubeconfig string
		tlsCert    string
		tlsKey     string
		tlsCA      string
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
				AgentID:     agentID,
				ClusterID:   clusterID,
				ServerAddr:  serverAddr,
				GrypeDBDir:  grypeDBDir,
				TLSCertFile: tlsCert,
				TLSKeyFile:  tlsKey,
				TLSCAFile:   tlsCA,
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
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Agent TLS certificate file (enables mTLS)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Agent TLS key file")
	cmd.Flags().StringVar(&tlsCA, "tls-ca", "", "CA certificate to verify server cert")
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
