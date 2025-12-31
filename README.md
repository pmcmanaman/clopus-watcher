# Clopus Watcher

A Kubernetes-native Claude Code watcher that monitors pods, detects errors, and applies hotfixes directly, or just writes a report on its findings.

## Overview

Clopus Watcher runs as a CronJob that:
1. Monitors pods across target namespaces (supports wildcards)
2. Detects degraded pods (CrashLoopBackOff, Error, etc.)
3. Reads logs to understand the error
4. In autonomous mode: execs into the pod, explores and applies a hotfix
5. In report mode: generates a detailed report with recommendations
6. Records findings to SQLite & provides a web dashboard

A separate Dashboard deployment provides a web UI to view all detected errors and applied fixes.

## Quick Start

### Prerequisites

- Kubernetes cluster
- Helm 3.0+
- Anthropic API key

### Deploy with Helm

```bash
# Add the Helm repository
helm repo add clopus https://pmcmanaman.github.io/clopus-watcher/
helm repo update

# Create namespace and API key secret
kubectl create namespace clopus-watcher
kubectl create secret generic anthropic-api-key \
  --from-literal=api-key=YOUR_API_KEY \
  -n clopus-watcher

# Install
helm install clopus-watcher clopus/clopus-watcher \
  --namespace clopus-watcher \
  --set auth.apiKey.existingSecret=anthropic-api-key
```

### Deploy with ArgoCD

```bash
# Create the API key secret first
kubectl create namespace clopus-watcher
kubectl create secret generic anthropic-api-key \
  --from-literal=api-key=YOUR_API_KEY \
  -n clopus-watcher

# Apply the ArgoCD Application
kubectl apply -f examples/argocd-application.yaml
```

See [examples/argocd-application.yaml](examples/argocd-application.yaml) for full configuration options.

## Configuration

### Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `watcher.schedule` | CronJob schedule | `*/5 * * * *` |
| `watcher.targetNamespaces` | Namespaces to monitor (supports wildcards) | `["default"]` |
| `watcher.excludeNamespaces` | Namespaces to exclude | `["kube-system", ...]` |
| `watcher.mode` | Mode: `autonomous` or `report` | `autonomous` |
| `watcher.proactiveChecks` | Enable proactive issue detection | `false` |
| `dashboard.enabled` | Enable web dashboard | `true` |
| `dashboard.ingress.enabled` | Enable ingress | `false` |
| `auth.mode` | Auth mode: `api-key`, `oauth-token`, or `credentials` | `api-key` |
| `persistence.enabled` | Enable persistent storage | `true` |
| `metrics.enabled` | Enable Prometheus metrics | `true` |

See [chart/README.md](chart/README.md) for full configuration reference.

### Namespace Wildcards

Monitor multiple namespaces with patterns:

```yaml
watcher:
  targetNamespaces:
    - production          # Exact match
    - "staging-*"         # All namespaces starting with "staging-"
    - "*-backend"         # All namespaces ending with "-backend"
    - "*"                 # All namespaces
  excludeNamespaces:
    - kube-system
    - "*-test"            # Exclude test namespaces
```

### Watcher Modes

**Autonomous Mode** (default): Detects issues and automatically applies fixes.

```yaml
watcher:
  mode: autonomous
```

**Report Mode**: Detects issues and provides recommendations without making changes.

```yaml
watcher:
  mode: report
  proactiveChecks: true  # Enable proactive checks
```

## Container Images

Images are published to GitHub Container Registry:

- **Watcher**: `ghcr.io/pmcmanaman/clopus-watcher:latest`
- **Dashboard**: `ghcr.io/pmcmanaman/clopus-watcher-dashboard:latest`

Tagged releases are also available (e.g., `v0.1.0`, `v0.1`, `v0`).

## Helm Repository

The Helm chart is available from:

**GitHub Pages:**
```bash
helm repo add clopus https://pmcmanaman.github.io/clopus-watcher/
```

**OCI Registry (GHCR):**
```bash
helm pull oci://ghcr.io/pmcmanaman/charts/clopus-watcher --version 0.1.0
```

## Dashboard Features

- Real-time monitoring of watcher runs
- View detected issues and applied fixes
- Pod grouping with collapsible sections
- Run comparison view
- Export data (CSV/JSON)
- Dark/light theme
- Prometheus metrics (`/metrics`)
- Keyboard shortcuts (press `?` for help)

## Development

### Building Images Locally

```bash
# Build watcher image
docker build -f Dockerfile.watcher -t clopus-watcher:dev .

# Build dashboard image
docker build -f Dockerfile.dashboard -t clopus-watcher-dashboard:dev .
```

### Local Development

```bash
# Dashboard
cd dashboard
go run main.go

# Run with local database
SQLITE_PATH=./watcher.db PORT=8080 go run main.go
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   CronJob    │    │  Dashboard   │    │    PVC       │  │
│  │   (Watcher)  │───▶│  (Web UI)    │◀──▶│  (SQLite)    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                              │
│         │                   │ /metrics                     │
│         ▼                   ▼                              │
│  ┌──────────────┐    ┌──────────────┐                     │
│  │ Target Pods  │    │  Prometheus  │                     │
│  │ (monitored)  │    │  (optional)  │                     │
│  └──────────────┘    └──────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

## License

[MIT License](LICENSE)
