.PHONY: proto build build-agent build-server docker-agent docker-server lint test

PROTO_DIR := pkg/proto
MODULE    := github.com/mental-lab/grumble

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/grumble.proto

build: build-agent build-server

build-agent:
	CGO_ENABLED=0 go build -o bin/grumble-agent ./cmd/agent

build-server:
	go build -o bin/grumble-server ./cmd/server

docker-agent:
	docker build -f deploy/Dockerfile.agent -t grumble-agent:latest .

docker-server:
	docker build -f deploy/Dockerfile.server -t grumble-server:latest .

lint:
	golangci-lint run ./...

test:
	go test ./...
