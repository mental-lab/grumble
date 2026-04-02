# grumble

> Multi-cluster vulnerability scanner powered by Grype. Grumbles when your clusters have CVEs.

Grumble is a lightweight, multi-cluster container vulnerability scanning system. It runs a small agent in each Kubernetes cluster that watches for running workloads, scans images with [Grype](https://github.com/anchore/grype), and streams results to a central server — giving you a single hotspot view across all your clusters.

## Architecture

```
[Cluster A]
  grumble-agent ──────────────────────────────→
                         gRPC (outbound)          grumble-server
[Cluster B]                                         ├── SQLite / Postgres
  grumble-agent ──────────────────────────────→     ├── HTTP API
                                                    └── Grafana dashboard
[Cluster C]
  grumble-agent ──────────────────────────────→
```

**Key design decisions (inspired by GitLab KAS):**
- Agents initiate outbound gRPC connections — no inbound firewall rules needed
- Works behind NAT, across clouds, and in air-gapped environments
- Bidirectional streaming — server can push config changes to agents
- Exponential backoff with jitter on reconnect

## Components

| Component | Description |
|---|---|
| `grumble-agent` | In-cluster agent: watches pods, scans images with Grype, streams results |
| `grumble-server` | Central aggregation server: receives results, exposes HTTP API for Grafana |

## Hotspot Scoring

Grumble scores images by **risk × blast radius**:

```
risk_score = (critical × 10 + high × 3 + medium) × pod_count
```

A critical CVE in 1 pod scores lower than a high CVE running in 200 pods across 10 teams. This surfaces what actually needs fixing first.

## Quick Start

### Run the server

```bash
go run ./cmd/server --grpc-addr=:9090 --http-addr=:8080 --db=/data/grumble.db
```

### Run an agent (with kubeconfig)

```bash
go run ./cmd/agent \
  --cluster-id=prod-us-east \
  --server=grumble-server:9090 \
  --kubeconfig=~/.kube/config
```

### Deploy to Kubernetes (via Helm)

```bash
# Deploy the agent to each cluster
helm install grumble-agent ./deploy/helm/agent \
  --set agent.clusterID=prod-us-east \
  --set agent.serverAddr=grumble.example.com:9090
```

## Building

```bash
# Generate gRPC code from proto
make proto

# Build binaries
make build

# Run tests
make test
```

## Container Images

Images are published automatically to [GitHub Container Registry](https://ghcr.io/mental-lab/grumble-agent) on every push to `main` and on version tags.

| Tag | When |
|-----|------|
| `sha-<commit>` | Every push to `main` |
| `v1.2.3` | On git tag `v1.2.3` |
| `1.2` | On git tag `v1.2.x` |

Every image is scanned with [Grype](https://github.com/anchore/grype) in CI. Builds fail on critical CVEs. Scan results are uploaded to GitHub Security → Code scanning.

**Build locally:**

```bash
make docker-agent
# produces grumble-agent:latest
```

**Deploy to a cluster:**

```bash
# 1. Ensure the image is available (built and pushed, or loaded into your cluster)
# 2. Install via Helm
helm install grumble-agent ./deploy/helm/agent \
  --set agent.clusterID=prod-us-east \
  --set agent.serverAddr=grumble.example.com:9090 \
  --set image.repository=ghcr.io/mental-lab/grumble-agent \
  --set image.tag=main
```

For local development clusters (e.g. Rancher Desktop / k3s):

```bash
# Build and import directly — no registry needed
docker build -f deploy/Dockerfile.agent -t grumble-agent:dev .
# For k3s: import into containerd
docker save grumble-agent:dev | sudo k3s ctr images import -

helm install grumble-agent ./deploy/helm/agent \
  --set agent.clusterID=local \
  --set agent.serverAddr=grumble-server:9090 \
  --set image.repository=grumble-agent \
  --set image.tag=dev \
  --set image.pullPolicy=Never
```

## Grafana

Point a [JSON API datasource](https://grafana.com/grafana/plugins/marcusolsson-json-datasource/) at your grumble-server HTTP address.

Available endpoints:
- `GET /hotspots` — images ranked by risk score (critical CVEs × pod count)
- `GET /clusters` — per-cluster summary
- `GET /inventory?cluster=<id>` — pod inventory for a cluster

<img width="1728" height="960" alt="image" src="https://github.com/user-attachments/assets/f5d058e1-12a5-4abb-9ad0-f3ce25c29d93" />


## Name

Grumble pays tribute to [Grype](https://github.com/anchore/grype). It grumbles loudly when it finds vulnerabilities in your clusters.
