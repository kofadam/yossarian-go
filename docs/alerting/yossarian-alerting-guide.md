# Yossarian Go - Complete Alerting Setup Guide

## 🎯 **Overview**

This guide covers **two alerting approaches** for Yossarian Go:

1. **Prometheus Operator Alerting** (AlertManager) - Infrastructure-focused
2. **Grafana Alerting** - Visualization-focused with more flexibility

Both can work together or independently. Let's start with understanding the architecture.

---

## 📐 **Architecture Comparison**

### **Prometheus Operator Flow**
```
Metrics → Prometheus → PrometheusRule → AlertManager → Notifications
   ↓                          ↓              ↓
ServiceMonitor          Alert States    Routing/Grouping
```

### **Grafana Alerting Flow**
```
Metrics → Prometheus → Grafana → Alert Rules → Contact Points → Notifications
   ↓                      ↓           ↓             ↓
Data Source          Query Panel   Conditions   Email/Slack/etc
```

---

## 🔧 **Part 1: Prometheus Operator Alerting (AlertManager)**

### **Step 1: Expose Metrics from Yossarian Go**

First, add a `/metrics` endpoint to your Go application:

**File: `main.go` - Add Prometheus metrics**

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    // Request counters
    httpRequestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "yossarian_http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status"},
    )

    // Upload metrics
    uploadSize = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "yossarian_upload_size_bytes",
            Help:    "Size of uploaded files in bytes",
            Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
        },
        []string{"file_type"},
    )

    processingTime = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "yossarian_processing_duration_seconds",
            Help:    "Time taken to process files",
            Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60},
        },
        []string{"operation"},
    )

    // Pattern detection metrics
    patternsDetected = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "yossarian_patterns_detected_total",
            Help: "Total number of sensitive patterns detected",
        },
        []string{"pattern_type"},
    )

    // Active sessions
    activeSessions = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "yossarian_active_sessions",
            Help: "Number of active user sessions",
        },
    )

    // Error counter
    errorsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "yossarian_errors_total",
            Help: "Total number of errors by type",
        },
        []string{"error_type"},
    )

    // AD lookup cache metrics
    adCacheHits = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "yossarian_ad_cache_hits_total",
            Help: "Total number of AD cache hits",
        },
    )

    adCacheMisses = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "yossarian_ad_cache_misses_total",
            Help: "Total number of AD cache misses",
        },
    )
)

func main() {
    // ... existing code ...

    // Add metrics endpoint
    http.Handle("/metrics", promhttp.Handler())

    log.Printf("Server starting on port %s with metrics on /metrics", port)
    log.Fatal(http.ListenAndServe(":"+port, nil))
}

// Example: Instrument your upload handler
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    startTime := time.Now()

    // ... existing upload logic ...

    // Record metrics
    httpRequestsTotal.WithLabelValues(r.Method, "/upload", "200").Inc()
    uploadSize.WithLabelValues(filepath.Ext(filename)).Observe(float64(fileSize))
    processingTime.WithLabelValues("upload").Observe(time.Since(startTime).Seconds())
    patternsDetected.WithLabelValues("ip_address").Add(float64(ipCount))
}
```

---

### **Step 2: Create ServiceMonitor**

Tell Prometheus Operator to scrape your metrics:

**File: `yossarian-servicemonitor.yaml`**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: yossarian-go
  namespace: yossarian
  labels:
    app: yossarian-go
    release: prometheus-operator  # Match your Prometheus release name
spec:
  selector:
    matchLabels:
      app: yossarian-go
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
---
apiVersion: v1
kind: Service
metadata:
  name: yossarian-go-metrics
  namespace: yossarian
  labels:
    app: yossarian-go
spec:
  selector:
    app: yossarian-go
  ports:
  - name: http
    port: 8080
    targetPort: 8080
```

**Apply:**
```bash
kubectl apply -f yossarian-servicemonitor.yaml
```

**Verify scraping:**
```bash
# Check if ServiceMonitor is detected
kubectl get servicemonitor -n yossarian

# Check Prometheus targets (port-forward to Prometheus)
kubectl port-forward -n monitoring svc/prometheus-operator-prometheus 9090:9090
# Open http://localhost:9090/targets and search for "yossarian"
```

---

### **Step 3: Create PrometheusRule (Alert Definitions)**

**File: `yossarian-alerts.yaml`**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: yossarian-alerts
  namespace: yossarian
  labels:
    app: yossarian-go
    release: prometheus-operator  # Important: Match your Prometheus release
spec:
  groups:
  - name: yossarian-application
    interval: 30s
    rules:
    
    # 1. High Error Rate
    - alert: YossarianHighErrorRate
      expr: |
        rate(yossarian_errors_total[5m]) > 0.1
      for: 2m
      labels:
        severity: warning
        component: application
      annotations:
        summary: "High error rate in Yossarian Go"
        description: "Error rate is {{ $value }} errors/sec (threshold: 0.1/sec)"
        runbook_url: "https://docs.company.com/runbooks/yossarian-errors"

    # 2. Slow File Processing
    - alert: YossarianSlowProcessing
      expr: |
        histogram_quantile(0.95, rate(yossarian_processing_duration_seconds_bucket[5m])) > 10
      for: 5m
      labels:
        severity: warning
        component: performance
      annotations:
        summary: "Slow file processing in Yossarian Go"
        description: "95th percentile processing time is {{ $value }}s (threshold: 10s)"

    # 3. No Metrics (Application Down)
    - alert: YossarianDown
      expr: |
        up{job="yossarian-go"} == 0
      for: 1m
      labels:
        severity: critical
        component: availability
      annotations:
        summary: "Yossarian Go is down"
        description: "Prometheus cannot scrape metrics from Yossarian Go for 1 minute"

    # 4. High Upload Volume
    - alert: YossarianHighUploadVolume
      expr: |
        rate(yossarian_http_requests_total{endpoint="/upload"}[5m]) > 10
      for: 5m
      labels:
        severity: info
        component: capacity
      annotations:
        summary: "High upload volume in Yossarian Go"
        description: "Upload rate is {{ $value }} requests/sec (threshold: 10/sec)"

    # 5. AD Cache Miss Rate
    - alert: YossarianHighCacheMissRate
      expr: |
        rate(yossarian_ad_cache_misses_total[5m]) / 
        (rate(yossarian_ad_cache_hits_total[5m]) + rate(yossarian_ad_cache_misses_total[5m])) > 0.3
      for: 10m
      labels:
        severity: warning
        component: database
      annotations:
        summary: "High AD cache miss rate in Yossarian Go"
        description: "Cache miss rate is {{ $value | humanizePercentage }} (threshold: 30%)"

    # 6. Pod Restart Loop
    - alert: YossarianPodRestartLoop
      expr: |
        rate(kube_pod_container_status_restarts_total{namespace="yossarian", pod=~"yossarian-go-.*"}[15m]) > 0.1
      for: 5m
      labels:
        severity: critical
        component: infrastructure
      annotations:
        summary: "Yossarian Go pod is restarting frequently"
        description: "Pod {{ $labels.pod }} has restarted {{ $value }} times in 15 minutes"

  - name: yossarian-database
    interval: 30s
    rules:
    
    # 7. DB Service Down
    - alert: YossarianDBServiceDown
      expr: |
        up{job="yossarian-db-service"} == 0
      for: 1m
      labels:
        severity: critical
        component: database
      annotations:
        summary: "Yossarian DB Service is down"
        description: "The database service is not responding to health checks"

    # 8. LDAP Sync Failing
    - alert: YossarianLDAPSyncFailed
      expr: |
        yossarian_ldap_sync_success == 0
      for: 30m
      labels:
        severity: warning
        component: integration
      annotations:
        summary: "LDAP sync is failing in Yossarian"
        description: "LDAP sync has not succeeded for 30 minutes"
```

**Apply:**
```bash
kubectl apply -f yossarian-alerts.yaml
```

**Verify alerts are loaded:**
```bash
# Check PrometheusRule
kubectl get prometheusrule -n yossarian

# View in Prometheus UI
kubectl port-forward -n monitoring svc/prometheus-operator-prometheus 9090:9090
# Open http://localhost:9090/alerts
```

---

### **Step 4: Configure AlertManager**

AlertManager handles **routing, grouping, and sending** alerts.

**File: `alertmanager-config.yaml`**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: alertmanager-prometheus-operator-alertmanager
  namespace: monitoring
type: Opaque
stringData:
  alertmanager.yaml: |
    global:
      resolve_timeout: 5m
      
    # Templates for alert messages
    templates:
    - '/etc/alertmanager/config/*.tmpl'

    # Routing tree
    route:
      receiver: 'default'
      group_by: ['alertname', 'cluster', 'service']
      group_wait: 10s        # Wait before sending first notification
      group_interval: 10s    # Wait before sending new alerts in same group
      repeat_interval: 12h   # Resend if still firing

      routes:
      # Critical alerts go to PagerDuty
      - match:
          severity: critical
        receiver: 'pagerduty'
        continue: true  # Also send to default receiver

      # Yossarian-specific alerts
      - match:
          app: yossarian-go
        receiver: 'yossarian-team'
        group_by: ['alertname', 'component']
        routes:
        # Database issues go to DB team too
        - match:
            component: database
          receiver: 'db-team'

    # Inhibition rules (suppress less severe alerts)
    inhibit_rules:
    - source_match:
        severity: 'critical'
      target_match:
        severity: 'warning'
      equal: ['alertname', 'namespace', 'service']

    # Receivers (notification destinations)
    receivers:
    - name: 'default'
      slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#alerts'
        title: '{{ template "slack.default.title" . }}'
        text: '{{ template "slack.default.text" . }}'
        send_resolved: true

    - name: 'yossarian-team'
      email_configs:
      - to: 'yossarian-team@company.com'
        from: 'alertmanager@company.com'
        smarthost: 'smtp.company.com:587'
        auth_username: 'alertmanager'
        auth_password: 'SECRET'
        headers:
          Subject: '[{{ .Status }}] Yossarian Alert: {{ .GroupLabels.alertname }}'
      slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#yossarian-alerts'
        username: 'Yossarian AlertManager'
        title: '[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }}'
        text: |-
          *Summary:* {{ range .Alerts }}{{ .Annotations.summary }}{{ end }}
          *Details:* {{ range .Alerts }}{{ .Annotations.description }}{{ end }}
          *Severity:* {{ .GroupLabels.severity }}
          *Component:* {{ .GroupLabels.component }}

    - name: 'pagerduty'
      pagerduty_configs:
      - service_key: 'YOUR-PAGERDUTY-SERVICE-KEY'
        description: '{{ template "pagerduty.default.description" . }}'

    - name: 'db-team'
      email_configs:
      - to: 'db-team@company.com'
        from: 'alertmanager@company.com'
        smarthost: 'smtp.company.com:587'
```

**Apply:**
```bash
kubectl apply -f alertmanager-config.yaml

# Restart AlertManager to pick up config
kubectl rollout restart statefulset/alertmanager-prometheus-operator-alertmanager -n monitoring
```

**Verify AlertManager:**
```bash
# Port-forward to AlertManager UI
kubectl port-forward -n monitoring svc/alertmanager-operated 9093:9093
# Open http://localhost:9093
```

---

## 🎨 **Part 2: Grafana Alerting**

Grafana alerting is **more flexible** and allows alerts based on **dashboard queries**.

### **Step 1: Configure Prometheus Data Source in Grafana**

```bash
# Port-forward to Grafana
kubectl port-forward -n monitoring svc/prometheus-operator-grafana 3000:80

# Login: admin / prom-operator (or check secret)
kubectl get secret -n monitoring prometheus-operator-grafana -o jsonpath="{.data.admin-password}" | base64 -d
```

**In Grafana UI:**
1. Go to **Configuration → Data Sources**
2. Click **Add data source → Prometheus**
3. URL: `http://prometheus-operator-prometheus.monitoring.svc:9090`
4. Click **Save & Test**

---

### **Step 2: Create Grafana Dashboard with Panels**

**File: `yossarian-dashboard.json`**

```json
{
  "dashboard": {
    "title": "Yossarian Go Monitoring",
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(yossarian_http_requests_total[5m])",
            "legendFormat": "{{ method }} {{ endpoint }}"
          }
        ],
        "alert": {
          "name": "High Request Rate",
          "conditions": [
            {
              "evaluator": {
                "params": [100],
                "type": "gt"
              },
              "operator": {
                "type": "and"
              },
              "query": {
                "params": ["A", "5m", "now"]
              },
              "reducer": {
                "params": [],
                "type": "avg"
              },
              "type": "query"
            }
          ],
          "executionErrorState": "alerting",
          "frequency": "1m",
          "handler": 1,
          "message": "Request rate exceeded 100 req/sec",
          "noDataState": "no_data",
          "notifications": [
            {"uid": "slack-channel"}
          ]
        }
      },
      {
        "id": 2,
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(yossarian_errors_total[5m])",
            "legendFormat": "{{ error_type }}"
          }
        ]
      }
    ]
  }
}
```

---

### **Step 3: Create Alert Rules in Grafana**

**Modern approach: Use Grafana Alerting (v9+)**

1. **Go to Alerting → Alert Rules → New Alert Rule**

2. **Query:**
   ```promql
   rate(yossarian_errors_total[5m]) > 0.1
   ```

3. **Conditions:**
   - **When**: `avg()` **of** query(A, 5m, now)
   - **Is above**: `0.1`

4. **Alert Details:**
   - **Name**: `Yossarian High Error Rate`
   - **Folder**: `Yossarian`
   - **Evaluation interval**: `1m`
   - **For**: `2m` (pending before firing)

5. **Annotations:**
   ```
   Summary: High error rate in Yossarian Go
   Description: Error rate is {{ $values.A }} errors/sec
   ```

6. **Contact Points**: Select your Slack/Email

---

### **Step 4: Create Contact Points**

**Alerting → Contact Points → New Contact Point**

#### **Slack Integration:**
```yaml
Name: yossarian-slack
Type: Slack
Webhook URL: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
Username: Grafana Yossarian Alerts
Channel: #yossarian-alerts
Title: [{{ .Status }}] {{ .Labels.alertname }}
Message: |
  *Summary:* {{ .Annotations.summary }}
  *Value:* {{ .Values }}
  *Labels:* {{ .Labels }}
```

#### **Email Integration:**
```yaml
Name: yossarian-email
Type: Email
Addresses: yossarian-team@company.com
Subject: [{{ .Status }}] Yossarian Alert: {{ .Labels.alertname }}
```

---

## 🧪 **Testing Your Alerts**

### **Test 1: Trigger High Error Rate**

```bash
# Generate errors by uploading invalid files
for i in {1..100}; do
  curl -X POST http://yossarian.local/upload \
    -F "file=@/dev/null" &
done

# Check Prometheus
kubectl port-forward -n monitoring svc/prometheus-operator-prometheus 9090:9090
# Query: rate(yossarian_errors_total[1m])
```

### **Test 2: Simulate Pod Down**

```bash
# Scale down deployment
kubectl scale deployment yossarian-go -n yossarian --replicas=0

# Wait 1 minute, check AlertManager
kubectl port-forward -n monitoring svc/alertmanager-operated 9093:9093
# Alert "YossarianDown" should fire
```

### **Test 3: Check Alert Routing**

```bash
# Send test alert to AlertManager
curl -X POST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{
    "labels": {
      "alertname": "TestAlert",
      "severity": "warning",
      "app": "yossarian-go"
    },
    "annotations": {
      "summary": "This is a test alert"
    }
  }]'
```

---

## 📊 **Recommended Alert Strategy**

### **Use Prometheus Operator for:**
- Infrastructure metrics (pod health, restarts)
- Low-level system alerts (CPU, memory)
- Multi-cluster alerting
- Long-term alert history

### **Use Grafana for:**
- Business metrics (user activity, uploads)
- Complex queries across multiple data sources
- Visual alert testing with dashboard panels
- Easier alert creation for non-Prometheus experts

### **Best Practice: Use Both!**
```
Prometheus Operator  → Critical infrastructure alerts → PagerDuty
Grafana Alerting     → Application metrics → Slack/Email
```

---

## 🚀 **Quick Start Checklist**

- [ ] Add `/metrics` endpoint to Yossarian Go
- [ ] Create ServiceMonitor
- [ ] Verify Prometheus is scraping metrics
- [ ] Create PrometheusRule with alerts
- [ ] Configure AlertManager routing
- [ ] Test alert firing with curl/scale
- [ ] Create Grafana dashboard
- [ ] Configure Grafana contact points
- [ ] Create Grafana alert rules
- [ ] Test end-to-end notification

---

## 🔍 **Debugging Tips**

**Prometheus not scraping?**
```bash
# Check ServiceMonitor selector
kubectl get servicemonitor yossarian-go -n yossarian -o yaml

# Check Service labels match
kubectl get svc yossarian-go-metrics -n yossarian -o yaml

# Check Prometheus config
kubectl get prometheus -n monitoring -o yaml | grep serviceMonitorSelector
```

**Alerts not firing?**
```bash
# Check PrometheusRule is loaded
kubectl get prometheusrule -n yossarian
kubectl describe prometheusrule yossarian-alerts -n yossarian

# Check alert status in Prometheus
# http://localhost:9090/alerts

# Check AlertManager logs
kubectl logs -n monitoring alertmanager-prometheus-operator-alertmanager-0
```

**Grafana alerts not working?**
```bash
# Check Grafana logs
kubectl logs -n monitoring deployment/prometheus-operator-grafana

# Verify data source connection
# Settings → Data Sources → Prometheus → Test

# Check alert rule evaluation
# Alerting → Alert Rules → Click rule → Show state history
```

---

## 📚 **Additional Resources**

- **Prometheus Operator**: https://prometheus-operator.dev/
- **AlertManager Config**: https://prometheus.io/docs/alerting/latest/configuration/
- **Grafana Alerting**: https://grafana.com/docs/grafana/latest/alerting/
- **PromQL Guide**: https://prometheus.io/docs/prometheus/latest/querying/basics/

---

**Need help with specific alert scenarios? Let me know!**
