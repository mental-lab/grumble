package server

import (
	"io"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	proto "github.com/mental-lab/grumble/pkg/proto"
)

// Server is the central aggregation service. It receives scan results
// from agents across all clusters and stores them for Grafana to query.
type Server struct {
	proto.UnimplementedGrumbleServerServer
	store *Store
	log   *zap.Logger
}

func New(store *Store, log *zap.Logger) *Server {
	return &Server{store: store, log: log}
}

func (s *Server) Run(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	proto.RegisterGrumbleServerServer(grpcServer, s)

	s.log.Info("grumble server listening", zap.String("addr", addr))
	return grpcServer.Serve(lis)
}

// Connect handles the bidirectional stream from an agent.
// The agent initiates the connection; we receive its messages and can
// push commands back down the same stream.
func (s *Server) Connect(stream proto.GrumbleServer_ConnectServer) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch p := msg.Payload.(type) {
		case *proto.AgentMessage_Register:
			s.log.Info("agent registered",
				zap.String("agent", msg.AgentId),
				zap.String("cluster", p.Register.ClusterId),
				zap.String("agentVersion", p.Register.AgentVersion))

		case *proto.AgentMessage_ScanResult:
			s.log.Info("received scan result",
				zap.String("cluster", msg.ClusterId),
				zap.String("image", p.ScanResult.Image),
				zap.Int("vulns", len(p.ScanResult.Vulns)))
			if err := s.store.SaveScanResult(p.ScanResult); err != nil {
				s.log.Error("failed to store scan result", zap.Error(err))
			}

		case *proto.AgentMessage_Inventory:
			s.log.Debug("received pod inventory",
				zap.String("cluster", msg.ClusterId),
				zap.Int("pods", len(p.Inventory.Pods)))
			if err := s.store.SaveInventory(msg.ClusterId, p.Inventory); err != nil {
				s.log.Error("failed to store inventory", zap.Error(err))
			}

		case *proto.AgentMessage_Heartbeat:
			s.store.UpdateHeartbeat(msg.AgentId, p.Heartbeat.Timestamp)
		}
	}
}
