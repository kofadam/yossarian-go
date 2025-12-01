# Yossarian Alerting - Testing & Troubleshooting Guide

## 🧪 **Quick Test Checklist**

Run through this checklist to verify your alerting setup:

### **Step 1: Verify Metrics Collection**

```bash
# 1. Check if ServiceMonitor exists
kubectl get servicemonitor yossarian-go -n yossarian

# Expected output:
# NAME           AGE
# yossarian-go   5m

# 2. Check if Prometheus can find the ServiceMonitor
kubectl port-forward -n monitoring svc/prometheus-operator-prometheus 9090:9090

# Open: http://localhost:9090/targets
# Search for "yossarian" - should show UP status

# 3. Test metrics endpoint directly
kubectl port-forward -n yossarian svc/yossarian-go 8080:8080
curl http://localhost:8080/metrics

# Expected: Should return Prometheus metrics format
# HELP yossarian_http_requests_total Total number of HTTP requests
# TYPE yossarian_http_requests_total counter
# yossarian_http_requests_total{method="GET",endpoint="/health"} 42
```

### **Step 2: Verify Alert Rules Loaded**

```bash
# 1. Check PrometheusRule exists
kubectl get prometheusrule yossarian-alerts -n yossarian

# 2. Verify rules are loaded in Prometheus
# http://localhost:9090/alerts
# Search for "Yossarian" - should show all your alert rules

# 3. Check rule syntax
kubectl get prometheusrule yossarian-alerts -n yossarian -o yaml | less
```

### **Step 3: Test Alert Firing**

```bash
# Trigger "YossarianDown" alert by scaling to 0
kubectl scale deployment yossarian-go -n yossarian --replicas=0

# Wait 2 minutes, then check:
# http://localhost:9090/alerts
# YossarianDown should show as FIRING

# Restore:
kubectl scale deployment yossarian-go -n yossarian --replicas=2
```

### **Step 4: Verify AlertManager Routing**

```bash
# 1. Check AlertManager is running
kubectl get pods -n monitoring | grep alertmanager

# 2. Port-forward to AlertManager UI
kubectl port-forward -n monitoring svc/alertmanager-operated 9093:9093

# Open: http://localhost:9093
# Should show active alerts

# 3. Send test alert
curl -X POST http://localhost:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{
    "labels": {
      "alertname": "TestYossarianAlert",
      "severity": "warning",
      "app": "yossarian-go",
      "component": "test"
    },
    "annotations": {
      "summary": "This is a test alert for Yossarian",
      "description": "Testing alert routing and notifications"
    },
    "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }]'

# Check if alert appears in AlertManager UI
# Check if you receive notification in Slack/Email
```

---

## 🔍 **Troubleshooting Common Issues**

### **Issue 1: Prometheus Not Scraping Metrics**

**Symptoms:**
- No data in Prometheus for Yossarian metrics
- Target shows as DOWN in Prometheus UI

**Debugging:**

```bash
# 1. Check if pods are running
kubectl get pods -n yossarian -l app=yossarian-go

# 2. Test metrics endpoint from inside cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://yossarian-go.yossarian.svc:8080/metrics

# 3. Check Service selector matches Deployment
kubectl get svc yossarian-go -n yossarian -o yaml | grep -A5 selector
kubectl get deployment yossarian-go -n yossarian -o yaml | grep -A5 labels

# 4. Check ServiceMonitor selector matches Service
kubectl get servicemonitor yossarian-go -n yossarian -o yaml | grep -A5 selector

# 5. Check Prometheus ServiceMonitor selector
kubectl get prometheus -n monitoring -o yaml | grep -A10 serviceMonitorSelector
```

**Fix:**
```bash
# If labels don't match, update them:
kubectl label svc yossarian-go -n yossarian app=yossarian-go --overwrite
kubectl label deployment yossarian-go -n yossarian app=yossarian-go --overwrite

# Restart Prometheus to pick up changes
kubectl rollout restart statefulset prometheus-prometheus-operator-prometheus -n monitoring
```

---

### **Issue 2: Alerts Not Showing in Prometheus**

**Symptoms:**
- PrometheusRule exists but alerts don't appear in Prometheus UI

**Debugging:**

```bash
# 1. Check PrometheusRule labels
kubectl get prometheusrule yossarian-alerts -n yossarian -o yaml | grep -A5 labels

# 2. Check what Prometheus expects
kubectl get prometheus -n monitoring -o yaml | grep -A10 ruleSelector

# 3. Check for syntax errors in rules
kubectl logs -n monitoring prometheus-prometheus-operator-prometheus-0 | grep -i error

# 4. Validate PromQL syntax
# http://localhost:9090/graph
# Enter each alert query manually to check for errors
```

**Fix:**
```bash
# Add required labels to PrometheusRule
kubectl label prometheusrule yossarian-alerts -n yossarian \
  prometheus=kube-prometheus \
  role=alert-rules

# Or update the rule selector in Prometheus CRD
kubectl edit prometheus prometheus-operator-prometheus -n monitoring
# Set: ruleSelector: {} (to select all rules)
```

---

### **Issue 3: Alerts Not Reaching AlertManager**

**Symptoms:**
- Alerts show FIRING in Prometheus but don't appear in AlertManager

**Debugging:**

```bash
# 1. Check Prometheus AlertManager configuration
# http://localhost:9090/config
# Look for "alertmanagers" section

# 2. Check AlertManager service
kubectl get svc -n monitoring | grep alertmanager

# 3. Test connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://alertmanager-operated.monitoring.svc:9093/-/healthy

# 4. Check Prometheus logs
kubectl logs -n monitoring prometheus-prometheus-operator-prometheus-0 | grep -i alertmanager
```

**Fix:**
```bash
# Ensure Prometheus knows about AlertManager
kubectl get prometheus -n monitoring -o yaml | grep -A5 alertmanagers

# Should show:
# alerting:
#   alertmanagers:
#   - name: alertmanager-operated
#     namespace: monitoring
#     port: web
```

---

### **Issue 4: AlertManager Not Sending Notifications**

**Symptoms:**
- Alerts appear in AlertManager but no Slack/Email received

**Debugging:**

```bash
# 1. Check AlertManager config
kubectl get secret alertmanager-prometheus-operator-alertmanager -n monitoring \
  -o jsonpath='{.data.alertmanager\.yaml}' | base64 -d

# 2. Check AlertManager logs
kubectl logs -n monitoring alertmanager-prometheus-operator-alertmanager-0 | tail -50

# Look for:
# - "Notify for" messages (successful sends)
# - "failed to send" errors
# - "connection refused" errors

# 3. Test Slack webhook manually
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Test alert from Yossarian alerting setup"
  }'
```

**Common Fixes:**

```yaml
# Issue: Wrong Slack webhook URL
# Fix: Update AlertManager config
kubectl edit secret alertmanager-prometheus-operator-alertmanager -n monitoring
# Update api_url with correct webhook

# Issue: SMTP auth failure
# Check username/password in global section

# Issue: Alerts inhibited
# Check inhibit_rules in config

# Issue: Wrong receiver selected
# Review route matching logic
```

---

### **Issue 5: Grafana Alerts Not Working**

**Symptoms:**
- Grafana alert rules show "Pending" or "NoData"

**Debugging:**

```bash
# 1. Check data source connection
# Grafana → Configuration → Data Sources → Prometheus → Test

# 2. Check alert rule query
# Alerting → Alert Rules → Click rule → Show query inspector

# 3. Check Grafana logs
kubectl logs -n monitoring deployment/prometheus-operator-grafana | grep -i alert

# 4. Verify notification channel
# Alerting → Contact Points → Test
```

**Fix:**
```bash
# Common issues:
# - Data source URL wrong: http://prometheus-operated.monitoring.svc:9090
# - Query returns no data: Test query in Explore first
# - Contact point not configured: Add webhook/email in Contact Points
# - Alert rule disabled: Check enable toggle in alert rule
```

---

## 🧰 **Useful Commands**

### **View Current Alert State**

```bash
# All alerts in Prometheus
kubectl port-forward -n monitoring svc/prometheus-operator-prometheus 9090:9090
# http://localhost:9090/alerts

# All alerts in AlertManager
kubectl port-forward -n monitoring svc/alertmanager-operated 9093:9093
# http://localhost:9093

# Query alert state via API
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | select(.labels.alertname | contains("Yossarian"))'
```

### **Silence Alerts**

```bash
# In AlertManager UI: http://localhost:9093
# Click "Silence" button → Set duration → Add comment

# Or via API:
curl -X POST http://localhost:9093/api/v1/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [
      {"name": "alertname", "value": "YossarianDown", "isRegex": false}
    ],
    "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "endsAt": "'$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)'",
    "comment": "Planned maintenance",
    "createdBy": "admin@company.com"
  }'
```

### **Force Alert Evaluation**

```bash
# Reload Prometheus rules
curl -X POST http://localhost:9090/-/reload

# Restart Prometheus to force re-evaluation
kubectl rollout restart statefulset prometheus-prometheus-operator-prometheus -n monitoring
```

### **Check Metric Cardinality**

```bash
# Count unique metric time series
curl -s http://localhost:9090/api/v1/label/__name__/values | jq '.data | length'

# Count Yossarian-specific metrics
curl -s http://localhost:9090/api/v1/label/__name__/values | jq '.data[] | select(. | contains("yossarian"))' | wc -l

# Check for high cardinality metrics
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job == "yossarian-go") | .health'
```

---

## 📊 **Validation Queries**

Run these in Prometheus to validate your setup:

```promql
# 1. Verify metrics are being scraped
up{job="yossarian-go"}

# 2. Check request rate
rate(yossarian_http_requests_total[5m])

# 3. Calculate error rate
sum(rate(yossarian_errors_total[5m])) / sum(rate(yossarian_http_requests_total[5m]))

# 4. Check cache hit rate
rate(yossarian_ad_cache_hits_total[5m]) / (rate(yossarian_ad_cache_hits_total[5m]) + rate(yossarian_ad_cache_misses_total[5m]))

# 5. Processing time P95
histogram_quantile(0.95, rate(yossarian_processing_duration_seconds_bucket[5m]))

# 6. Memory usage percentage
container_memory_working_set_bytes{namespace="yossarian",pod=~"yossarian-go-.*"} / container_spec_memory_limit_bytes{namespace="yossarian",pod=~"yossarian-go-.*"}
```

---

## 🎯 **Best Practices Checklist**

- [ ] **Metrics are scraped** - Verify in Prometheus targets
- [ ] **Labels are consistent** - ServiceMonitor, Service, Deployment all match
- [ ] **Alert thresholds are realistic** - Test with actual traffic
- [ ] **Runbook URLs added** - Every alert has documentation
- [ ] **Severity levels correct** - Critical = pages, Warning = tickets, Info = FYI
- [ ] **Notifications tested** - Slack/Email actually deliver
- [ ] **Inhibition rules set** - Prevent alert storms
- [ ] **Silences documented** - Track planned maintenance
- [ ] **Dashboard created** - Visualize metrics in Grafana
- [ ] **Team trained** - Everyone knows how to respond

---

## 🚨 **Emergency Procedures**

### **Disable All Alerts Temporarily**

```bash
# Silence all Yossarian alerts for 2 hours
curl -X POST http://localhost:9093/api/v1/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [
      {"name": "alertname", "value": "Yossarian.*", "isRegex": true}
    ],
    "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "endsAt": "'$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)'",
    "comment": "Emergency maintenance",
    "createdBy": "oncall@company.com"
  }'
```

### **Stop Alert Spam**

```bash
# Scale down AlertManager temporarily
kubectl scale statefulset alertmanager-prometheus-operator-alertmanager -n monitoring --replicas=0

# Restore when ready
kubectl scale statefulset alertmanager-prometheus-operator-alertmanager -n monitoring --replicas=1
```

### **Reset Alert State**

```bash
# Clear all active alerts in AlertManager
curl -X DELETE http://localhost:9093/api/v1/alerts

# Restart AlertManager
kubectl rollout restart statefulset alertmanager-prometheus-operator-alertmanager -n monitoring
```

---

**Need help with a specific issue? Share the error logs and I'll help debug!**
