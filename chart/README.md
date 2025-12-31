# Clopus Watcher Helm Chart

Kubernetes auto-healing powered by Claude AI. Monitors pods, detects issues, and automatically applies fixes.

## Prerequisites

- Kubernetes 1.21+
- Helm 3.0+
- Anthropic API key or Claude credentials

## Installation

```bash
# Add your API key
kubectl create secret generic anthropic-api-key \
  --from-literal=api-key=YOUR_API_KEY \
  -n clopus-watcher

# Install the chart
helm install clopus-watcher ./chart \
  --namespace clopus-watcher \
  --set auth.apiKey.existingSecret=anthropic-api-key
```

## Configuration

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace.create` | Create namespace | `true` |
| `namespace.name` | Namespace name | `clopus-watcher` |

### Watcher Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `watcher.schedule` | CronJob schedule | `*/5 * * * *` |
| `watcher.targetNamespaces` | Namespaces to monitor (supports wildcards) | `["default"]` |
| `watcher.excludeNamespaces` | Namespaces to exclude | `["kube-system", "kube-public", "kube-node-lease"]` |
| `watcher.mode` | Mode: `autonomous` or `report` | `autonomous` |
| `watcher.proactiveChecks` | Enable proactive issue detection | `false` |
| `watcher.image.repository` | Watcher image | `ghcr.io/pmcmanaman/clopus-watcher` |
| `watcher.image.tag` | Image tag | `latest` |

### Dashboard Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `dashboard.enabled` | Enable dashboard | `true` |
| `dashboard.replicas` | Dashboard replicas | `1` |
| `dashboard.service.type` | Service type | `ClusterIP` |
| `dashboard.service.port` | Service port | `80` |
| `dashboard.ingress.enabled` | Enable ingress | `false` |

### Database Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.retentionDays` | Days to keep run history (0 to disable) | `30` |

### Authentication

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.mode` | Auth mode: `api-key`, `oauth-token`, or `credentials` | `api-key` |
| `auth.apiKey.existingSecret` | Existing secret with API key | `""` |
| `auth.apiKey.secretKey` | Key in secret | `api-key` |
| `auth.oauthToken.existingSecret` | Existing secret with OAuth token | `""` |
| `auth.oauthToken.secretKey` | Key in secret | `oauth-token` |

### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistence | `true` |
| `persistence.size` | PVC size | `1Gi` |
| `persistence.storageClassName` | Storage class | `""` |

### Metrics

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.enabled` | Enable Prometheus metrics | `true` |
| `metrics.serviceMonitor.enabled` | Create ServiceMonitor | `false` |
| `metrics.serviceMonitor.interval` | Scrape interval | `30s` |

## Examples

### Monitor Multiple Namespaces

```yaml
watcher:
  targetNamespaces:
    - production
    - staging
    - "app-*"  # All namespaces starting with "app-"
  excludeNamespaces:
    - kube-system
    - "*-test"  # Exclude test namespaces
```

### Report-Only Mode

```yaml
watcher:
  mode: report  # Detect issues but don't fix them
  proactiveChecks: true
```

### Enable Prometheus Monitoring

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
    labels:
      release: prometheus
```

### Ingress with TLS

```yaml
dashboard:
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: clopus.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: clopus-tls
        hosts:
          - clopus.example.com
```

## Exposed Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `clopus_runs_total` | Counter | namespace, status, mode | Total watcher runs |
| `clopus_errors_total` | Counter | namespace, error_type | Errors detected |
| `clopus_fixes_total` | Counter | namespace, status | Fixes attempted |
| `clopus_run_duration_seconds` | Histogram | namespace, mode | Run duration |
| `clopus_last_run_timestamp` | Gauge | namespace | Last run timestamp |
| `clopus_pods_monitored` | Gauge | namespace | Pods monitored |
| `clopus_active_errors` | Gauge | namespace | Active errors |

## Uninstalling

```bash
helm uninstall clopus-watcher -n clopus-watcher
kubectl delete namespace clopus-watcher
```

## Upgrading

```bash
helm upgrade clopus-watcher ./chart -n clopus-watcher
```
