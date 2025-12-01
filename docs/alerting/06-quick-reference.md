# Yossarian Alerting - Quick Reference Cheat Sheet

## 🎯 **Architecture Overview**

```
┌─────────────────────────────────────────────────────────────┐
│                    ALERTING FLOW                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Yossarian Go App                                          │
│  └─> /metrics endpoint (port 8080)                        │
│       │                                                     │
│       ▼                                                     │
│  ServiceMonitor (tells Prometheus where to scrape)        │
│       │                                                     │
│       ▼                                                     │
│  Prometheus (scrapes metrics, evaluates rules)            │
│  ├─> PrometheusRule (alert definitions)                   │
│  └─> Evaluates every 30s                                   │
│       │                                                     │
│       ▼                                                     │
│  AlertManager (groups, routes, sends)                     │
│  ├─> Routes based on severity/labels                      │
│  ├─> Groups similar alerts                                │
│  └─> Sends to Slack/Email/PagerDuty                       │
│       │                                                     │
│       ▼                                                     │
│  Notifications (Slack/Email/PagerDuty)                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📝 **Essential Commands**

### **Check Status**

```bash
# Check if metrics are being scraped
kubectl get servicemonitor yossarian-go -n yossarian

# Check if alerts are loaded
kubectl get prometheusrule yossarian-alerts -n yossarian

# Port-forward to Prometheus
kubectl port-forward -n monitoring svc/prometheus-operator-prometheus 9090:9090

# Port-forward to AlertManager
kubectl port-forward -n monitoring svc/alertmanager-operated 9093:9093

# Port-forward to Grafana
kubectl port-forward -n monitoring svc/prometheus-operator-grafana 3000:80
```

### **View Alerts**

```bash
# Prometheus UI - See all alert rules and states
http://localhost:9090/alerts

# AlertManager UI - See active/silenced alerts
http://localhost:9093

# Query alert state via CLI
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | select(.labels.alertname | contains("Yossarian"))'
```

### **Test Alerting**

```bash
# Trigger YossarianDown alert
kubectl scale deployment yossarian-go -n yossarian --replicas=0

# Send manual test alert
curl -X POST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{"labels":{"alertname":"TestAlert","severity":"warning"},"annotations":{"summary":"Test"}}]'

# Restore deployment
kubectl scale deployment yossarian-go -n yossarian --replicas=2
```

---

## 🔧 **Configuration Files**

### **1. ServiceMonitor** → Tells Prometheus where to scrape

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: yossarian-go
  namespace: yossarian
  labels:
    app: yossarian-go
    release: prometheus-operator  # MUST match Prometheus release label
spec:
  selector:
    matchLabels:
      app: yossarian-go  # MUST match Service labels
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

**Apply:** `kubectl apply -f servicemonitor.yaml`

---

### **2. PrometheusRule** → Defines alert conditions

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: yossarian-alerts
  namespace: yossarian
  labels:
    prometheus: kube-prometheus  # MUST match Prometheus ruleSelector
    role: alert-rules
spec:
  groups:
  - name: yossarian
    interval: 30s
    rules:
    - alert: YossarianDown
      expr: up{job="yossarian-go"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Yossarian is down"
```

**Apply:** `kubectl apply -f prometheusrule.yaml`

---

### **3. AlertManager Config** → Routes alerts to receivers

```yaml
route:
  receiver: 'default'
  routes:
  - match:
      severity: critical
    receiver: 'pagerduty'
  - match_re:
      alertname: 'Yossarian.*'
    receiver: 'yossarian-team'

receivers:
- name: 'yossarian-team'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
    channel: '#yossarian-alerts'
```

**Apply:** `kubectl create secret generic alertmanager-config --from-file=alertmanager.yaml -n monitoring`

---

## 🐛 **Troubleshooting Decision Tree**

```
┌─────────────────────────────────────┐
│ Are metrics showing in Prometheus? │
└────────────┬────────────────────────┘
             │
             ├─ NO → Check ServiceMonitor
             │       ├─ Labels match Service?
             │       ├─ Service selector matches Deployment?
             │       └─ Prometheus has correct serviceMonitorSelector?
             │
             └─ YES → Are alerts showing in Prometheus UI?
                      │
                      ├─ NO → Check PrometheusRule
                      │       ├─ Labels match ruleSelector?
                      │       ├─ PromQL syntax valid?
                      │       └─ Check Prometheus logs for errors
                      │
                      └─ YES → Do alerts appear in AlertManager?
                               │
                               ├─ NO → Check AlertManager connection
                               │       ├─ Service exists?
                               │       ├─ Prometheus alertmanagers config?
                               │       └─ Network policies blocking?
                               │
                               └─ YES → Are notifications sent?
                                        │
                                        ├─ NO → Check AlertManager config
                                        │       ├─ Webhook URL correct?
                                        │       ├─ SMTP credentials valid?
                                        │       ├─ Route matching correctly?
                                        │       └─ Check AlertManager logs
                                        │
                                        └─ YES → SUCCESS! 🎉
```

---

## ⚡ **Common Label Matching Issues**

### **Problem: ServiceMonitor not selecting Service**

```bash
# Check ServiceMonitor selector
kubectl get servicemonitor yossarian-go -n yossarian -o jsonpath='{.spec.selector}'

# Check Service labels
kubectl get svc yossarian-go -n yossarian -o jsonpath='{.metadata.labels}'

# FIX: Ensure they match
kubectl label svc yossarian-go -n yossarian app=yossarian-go --overwrite
```

### **Problem: Prometheus not loading PrometheusRule**

```bash
# Check Prometheus ruleSelector
kubectl get prometheus -n monitoring -o jsonpath='{.spec.ruleSelector}'

# Check PrometheusRule labels
kubectl get prometheusrule yossarian-alerts -n yossarian -o jsonpath='{.metadata.labels}'

# FIX: Add matching labels
kubectl label prometheusrule yossarian-alerts -n yossarian prometheus=kube-prometheus
```

---

## 📊 **Essential PromQL Queries**

```promql
# Application is up
up{job="yossarian-go"}

# Request rate (requests per second)
rate(yossarian_http_requests_total[5m])

# Error rate percentage
(sum(rate(yossarian_errors_total[5m])) / sum(rate(yossarian_http_requests_total[5m]))) * 100

# P95 processing time
histogram_quantile(0.95, rate(yossarian_processing_duration_seconds_bucket[5m]))

# Memory usage percentage
(container_memory_working_set_bytes{namespace="yossarian"} / container_spec_memory_limit_bytes{namespace="yossarian"}) * 100

# Cache hit rate
rate(yossarian_ad_cache_hits_total[5m]) / (rate(yossarian_ad_cache_hits_total[5m]) + rate(yossarian_ad_cache_misses_total[5m]))

# Pod restart count
rate(kube_pod_container_status_restarts_total{namespace="yossarian"}[15m])
```

---

## 🚨 **Alert Severity Levels**

| Severity | When to Use | Response | Examples |
|----------|------------|----------|----------|
| **critical** | Service completely down or critical functionality broken | Page on-call immediately | App down, DB unavailable, Pod crash loop |
| **warning** | Degraded performance or approaching limits | Create ticket, investigate within hours | High error rate, slow processing, high memory |
| **info** | FYI notifications, capacity planning | No immediate action, review weekly | High upload volume, pattern trends |

---

## 📧 **Notification Channels**

### **Slack Webhook**

```yaml
slack_configs:
- api_url: 'https://hooks.slack.com/services/T00/B00/XXX'
  channel: '#alerts'
  username: 'AlertManager'
  title: '[{{ .Status }}] {{ .GroupLabels.alertname }}'
  text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

**Get webhook:** Slack → Apps → Incoming Webhooks → Add to Channel

### **Email SMTP**

```yaml
email_configs:
- to: 'team@company.com'
  from: 'alertmanager@company.com'
  smarthost: 'smtp.gmail.com:587'
  auth_username: 'alertmanager@company.com'
  auth_password: 'app-specific-password'
  headers:
    Subject: '[{{ .Status }}] {{ .GroupLabels.alertname }}'
```

### **PagerDuty**

```yaml
pagerduty_configs:
- service_key: 'YOUR_INTEGRATION_KEY'
  description: '{{ template "pagerduty.default.description" . }}'
```

**Get integration key:** PagerDuty → Services → Integrations → Prometheus

---

## 🎛️ **AlertManager Routing Logic**

```yaml
route:
  receiver: 'default'           # Fallback if no routes match
  group_by: ['alertname']       # Group alerts by these labels
  group_wait: 30s               # Wait before sending first alert
  group_interval: 5m            # Wait before sending new alerts in group
  repeat_interval: 12h          # Resend if still firing
  
  routes:
  - match:                      # Exact match
      severity: critical
    receiver: 'pagerduty'
    
  - match_re:                   # Regex match
      alertname: 'Yossarian.*'
    receiver: 'yossarian-team'
```

**Evaluation order:**
1. Check `match` conditions (exact)
2. Check `match_re` conditions (regex)
3. Use first matching route
4. If `continue: true`, also check subsequent routes
5. Fall back to default receiver

---

## 🔕 **Silence Alerts**

### **Via UI** (Easiest)

1. Open AlertManager: `http://localhost:9093`
2. Click "Silence" button next to alert
3. Set duration (e.g., 2 hours)
4. Add comment: "Planned maintenance"
5. Click "Create"

### **Via API**

```bash
curl -X POST http://localhost:9093/api/v1/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [
      {"name": "alertname", "value": "YossarianDown", "isRegex": false}
    ],
    "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "endsAt": "'$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)'",
    "comment": "Planned deployment",
    "createdBy": "admin@company.com"
  }'
```

### **List Active Silences**

```bash
curl -s http://localhost:9093/api/v1/silences | jq '.data[] | {id, comment, endsAt}'
```

### **Delete Silence**

```bash
SILENCE_ID="abc-123-def"
curl -X DELETE http://localhost:9093/api/v1/silence/${SILENCE_ID}
```

---

## 📱 **Quick Response Playbook**

### **Alert: YossarianDown**

1. Check pod status: `kubectl get pods -n yossarian`
2. Check logs: `kubectl logs -n yossarian deployment/yossarian-go --tail=100`
3. If crashing: Check resource limits, OOM kills
4. If not found: Check if deployment was scaled down
5. Escalate if infrastructure issue

### **Alert: YossarianHighErrorRate**

1. Check error types: `rate(yossarian_errors_total[5m])`
2. Review recent logs: `kubectl logs -n yossarian deployment/yossarian-go | grep ERROR`
3. Check for pattern: User error vs system error
4. If system: Check dependencies (DB, LDAP)
5. If persistent: Roll back recent deployment

### **Alert: YossarianSlowProcessing**

1. Check file sizes: Histogram of upload sizes
2. Check AD cache hit rate: Should be >70%
3. Check memory: May need more resources
4. Review recent uploads for abnormal patterns
5. Consider increasing cache size or resources

---

## 🔑 **Key Files Reference**

```
yossarian-alerting/
├── 01-servicemonitor.yaml       # Prometheus scrape config
├── 02-prometheusrule.yaml       # Alert definitions
├── 03-alertmanager-config.yaml  # Notification routing
├── 04-grafana-dashboard.json    # Visualization
└── 05-testing-guide.md          # Troubleshooting steps
```

**Apply all:**
```bash
kubectl apply -f 01-servicemonitor.yaml
kubectl apply -f 02-prometheusrule.yaml
kubectl create secret generic alertmanager-config \
  --from-file=alertmanager.yaml=03-alertmanager-config.yaml \
  -n monitoring --dry-run=client -o yaml | kubectl apply -f -
```

---

## 🎓 **Learning Resources**

- **Prometheus Docs**: https://prometheus.io/docs/
- **AlertManager Config**: https://prometheus.io/docs/alerting/latest/configuration/
- **PromQL Basics**: https://prometheus.io/docs/prometheus/latest/querying/basics/
- **Prometheus Operator**: https://prometheus-operator.dev/
- **Grafana Alerting**: https://grafana.com/docs/grafana/latest/alerting/

---

## ✅ **Final Checklist**

- [ ] Metrics endpoint accessible (`/metrics`)
- [ ] ServiceMonitor created and labels match
- [ ] Prometheus scraping successfully (check `/targets`)
- [ ] PrometheusRule created and loaded (check `/alerts`)
- [ ] AlertManager config applied
- [ ] Test alert fires and sends notification
- [ ] Grafana dashboard imported
- [ ] Team notified of alert channels
- [ ] Runbooks documented for each alert
- [ ] Escalation paths defined

---

**🚀 You're all set! Start monitoring Yossarian with confidence!**
