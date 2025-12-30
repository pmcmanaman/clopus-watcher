## PROACTIVE CHECKS (Potential Issues)
**Note:** When proactive checks are enabled, include these in your report with type="proactive".
These checks identify risks BEFORE they cause failures. Report these as type="proactive".

### Resource Risks
```bash
# Check pods approaching resource limits
kubectl top pods -n $TARGET_NAMESPACE 2>/dev/null
# Compare against limits
kubectl get pods -n $TARGET_NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].resources.limits}{"\n"}{end}'
```
| Check | Severity | Risk |
|-------|----------|------|
| Memory usage >80% of limit | Warning | OOM incoming |
| CPU usage >80% of limit | Warning | Throttling incoming |
| No resource limits defined | Warning | Unbounded resource usage |
| No resource requests defined | Info | Poor scheduling decisions |

### Storage Risks
```bash
kubectl get pvc -n $TARGET_NAMESPACE
kubectl exec <pod> -- df -h 2>/dev/null || true
```
| Check | Severity | Risk |
|-------|----------|------|
| PVC >80% full | Warning | Disk full incoming |
| PVC >90% full | Critical | Imminent disk failure |

### Certificate Expiry
```bash
kubectl get secrets -n $TARGET_NAMESPACE -o json | grep -i tls
kubectl get ingress -n $TARGET_NAMESPACE -o jsonpath='{.items[*].spec.tls[*].secretName}'
```
| Check | Severity | Risk |
|-------|----------|------|
| Cert expires <30 days | Info | Plan renewal |
| Cert expires <7 days | Warning | Renew soon |
| Cert expires <24 hours | Critical | Imminent TLS failure |

### High Availability Risks
```bash
kubectl get deployments -n $TARGET_NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.status.readyReplicas}{"\n"}{end}'
kubectl get pdb -n $TARGET_NAMESPACE 2>/dev/null || echo "No PDBs"
kubectl get hpa -n $TARGET_NAMESPACE 2>/dev/null || echo "No HPAs"
```
| Check | Severity | Risk |
|-------|----------|------|
| Deployment with replicas=1 | Warning | No HA, single point of failure |
| No PodDisruptionBudget | Info | Risk during node maintenance |
| HPA at maxReplicas | Warning | Cannot scale further |
| Available < desired replicas | Warning | Degraded capacity |

### Security Risks
```bash
kubectl get pods -n $TARGET_NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].securityContext}{"\n"}{end}'
kubectl get pods -n $TARGET_NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'
```
| Check | Severity | Risk |
|-------|----------|------|
| Container running as root | Warning | Security vulnerability |
| No securityContext defined | Info | Best practice violation |
| Image using `:latest` tag | Warning | Unpredictable deployments |
| Image with no tag | Warning | Unpredictable deployments |
| Privileged container | Warning | Security risk |

### Configuration Risks
```bash
kubectl get pods -n $TARGET_NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].livenessProbe}{"\t"}{.spec.containers[*].readinessProbe}{"\n"}{end}'
```
| Check | Severity | Risk |
|-------|----------|------|
| No livenessProbe defined | Warning | Undetected application hangs |
| No readinessProbe defined | Warning | Traffic sent to unready pods |
| Probe timeouts too short (<5s) | Info | False positive probe failures |

### Cluster Capacity
```bash
kubectl describe nodes | grep -A10 "Allocated resources"
kubectl get resourcequota -n $TARGET_NAMESPACE 2>/dev/null || echo "No quotas"
```
| Check | Severity | Risk |
|-------|----------|------|
| Node memory pressure | Warning | Pod evictions incoming |
| Node disk pressure | Warning | Pod evictions incoming |
| Node PID pressure | Warning | Process failures incoming |
| ResourceQuota >80% used | Warning | Deployment failures soon |
| ResourceQuota >95% used | Critical | Cannot deploy new pods |

### Proactive Issue Recommendations
| Risk | Recommendation |
|------|----------------|
| Memory >80% of limit | Increase memory limits or optimize application memory usage |
| CPU >80% of limit | Increase CPU limits or optimize application performance |
| No resource limits | Add resource limits to prevent unbounded usage |
| No resource requests | Add resource requests for proper scheduling |
| PVC >80% full | Expand PVC, add log rotation, clean up old data |
| Cert expires <7 days | Renew certificate, check cert-manager status |
| Single replica | Increase replicas to 2+ for high availability |
| No PodDisruptionBudget | Add PDB to ensure availability during maintenance |
| HPA at max | Increase maxReplicas or add more node capacity |
| No livenessProbe | Add livenessProbe to detect hung processes |
| No readinessProbe | Add readinessProbe to prevent traffic to unready pods |
| Running as root | Set securityContext.runAsNonRoot: true |
| Using :latest tag | Pin to specific image version for reproducibility |
| Privileged container | Remove privileged: true unless absolutely required |
| Node pressure | Add nodes or reduce workload on affected node |
| Quota >80% | Request quota increase or clean up unused resources |

## EXTENDED REPORT FORMAT (with Proactive Checks)
When proactive checks are enabled, use this extended report format:
```
===REPORT_START===
{
  "pod_count": <number of pods checked>,
  "error_count": <number of current errors>,
  "warning_count": <number of proactive warnings>,
  "fix_count": <number of fixes applied>,
  "status": "<ok|fixed|failed|issues_found|warnings>",
  "summary": "<one sentence summary>",
  "details": [
    {
      "pod": "<name or 'cluster' for cluster-wide>",
      "issue": "<description>",
      "type": "<current|proactive>",
      "severity": "<critical|warning|info>",
      "category": "<application|config|resources|networking|scheduling|security|storage|availability|capacity>",
      "recommendation": "<specific fix>"
    }
  ]
}
===REPORT_END===
```

Additional status:
- "warnings": No current errors but proactive warnings found

Additional categories:
- "availability": Replicas, PDB, HPA, single points of failure
- "capacity": Node resources, quotas, cluster limits
