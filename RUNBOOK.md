# Grumble Local Runbook

## Architecture

```
[k8s cluster]                    [docker-compose on host]
  grumble-agent  ──gRPC:9090──▶  grumble-server  ──HTTP:8080──▶  grafana:3000
  (scans images)                  (stores results in SQLite)        (dashboard)
```

The agent runs **inside** Kubernetes. The server and Grafana run **outside** via docker-compose.
The agent reaches the host using `host.rancher-desktop.internal:9090`.

---

## Check Everything Is Running

```bash
# 1. Agent pod is running
kubectl get pods -n default -l app=grumble-agent

# 2. Server + Grafana are up
docker compose -f deploy/docker-compose.yml ps

# 3. Agent logs (look for "scanning image" or "connected to grumble server")
kubectl logs -n default -l app=grumble-agent --tail=20

# 4. Server is responding
curl http://localhost:8080/stats
```

Expected healthy output from `/stats`:
```json
{"clusters":1,"images_scanned":13,"critical_total":15,"high_total":90,...}
```

---

## Check Scan Status

```bash
# Overview stats
curl http://localhost:8080/stats

# All images and their scan status
curl http://localhost:8080/images

# All clusters registered
curl http://localhost:8080/clusters

# Vulnerabilities
curl http://localhost:8080/vulns

# Hotspots (most vulnerable images)
curl http://localhost:8080/hotspots
```

Scan statuses:
- `pending` — discovered but not yet scanned (Grype still working)
- `scanned` — complete, results available

---

## Deploy / Redeploy the Agent

```bash
# Full deploy with all required values
helm upgrade grumble-agent deploy/helm/agent \
  --namespace default \
  -f deploy/helm/agent/values.yaml \
  --set image.repository=ghcr.io/mental-lab/grumble-agent \
  --set image.tag=sha-eef5102 \
  --set image.pullPolicy=IfNotPresent \
  --set agent.clusterID=local \
  --set agent.serverAddr=host.rancher-desktop.internal:9090 \
  --set agent.dev=true \
  --set resources.limits.memory=3Gi \
  --set resources.requests.memory=512Mi
```

> **Note:** `--set agent.dev=true` disables TLS and OIDC — required when server runs with `--dev` flag.

---

## Force a Fresh Scan

```bash
# Restart the agent — triggers a full re-scan on startup
kubectl rollout restart deployment/grumble-agent-grumble-agent -n default

# Watch it come back up
kubectl get pods -n default -w
```

---

## Clean Up Evicted / Failed Pods

```bash
# Delete all failed pods (evicted, error, oomkilled)
kubectl delete pods -n default --field-selector=status.phase=Failed
```

---

## Troubleshooting

### Agent keeps restarting (CrashLoopBackOff)

```bash
# Check why it crashed
kubectl describe pod -n default -l app=grumble-agent | grep -A5 "Last State:"

# View previous container logs
kubectl logs -n default <pod-name> --previous
```

Common causes:
| Symptom | Fix |
|---------|-----|
| `OOMKilled` | Increase memory: `--set resources.limits.memory=3Gi` |
| `clusterID must not be empty` | Add `--set agent.clusterID=local` |
| `credentials require transport level security` | Add `--set agent.dev=true` |
| `connection lost, retrying` | Wrong `serverAddr` — use `host.rancher-desktop.internal:9090` |
| `ErrImageNeverPull` | Image not built locally — use ghcr.io image with `pullPolicy=IfNotPresent` |

### Dashboard not updating

1. Check agent is connected: `kubectl logs -n default -l app=grumble-agent --tail=10`
2. Check server has data: `curl http://localhost:8080/stats`
3. Check images are scanning: `curl http://localhost:8080/images` — look for `scanned` status
4. Scans take a few minutes — Grype downloads a vulnerability DB on first run

### Server/Grafana not running

```bash
cd /Users/jefferson.jones/.multiclaude/repos/grumble
docker compose up -d
```

---

## Current Helm Values (as deployed)

```
image:        ghcr.io/mental-lab/grumble-agent:sha-eef5102
pullPolicy:   IfNotPresent
clusterID:    local
serverAddr:   host.rancher-desktop.internal:9090
dev:          true
memory limit: 3Gi
grypeDBDir:   /tmp/grype-db (backed by PVC)
```

View live values:
```bash
helm get values grumble-agent -n default
```

---

## Grafana Dashboard

Open: http://localhost:3000

The dashboard auto-refreshes every 5 minutes. Use the cluster/severity filters at the top.
Data comes from the Infinity datasource pointed at `http://grumble-server:8080`.
