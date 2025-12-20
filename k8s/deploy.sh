#!/bin/bash
# Yossarian Go v0.10.0 Deployment Script

set -e  # Exit on error

echo "🚀 Deploying Yossarian Go v0.10.0..."
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ Error: kubectl not found. Please install kubectl first."
    exit 1
fi

# Apply resources in order
echo "📦 Creating namespace..."
kubectl apply -f 01-namespace.yaml

echo "📝 Creating ConfigMap..."
kubectl apply -f 02-configmap.yaml

echo "🔐 Creating Secrets..."
kubectl apply -f 03-secrets.yaml

echo "📜 Creating CA Bundle ConfigMap..."
kubectl apply -f 04-ca-bundle-configmap.yaml

echo "💾 Creating PVCs (this may take a moment)..."
kubectl apply -f 05-pvcs.yaml

# Wait for PVCs to be bound
echo "⏳ Waiting for PVCs to be bound..."
kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/yossarian-db-pvc -n yossarian-go --timeout=60s || echo "⚠️  Warning: DB PVC not bound yet"
kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/yossarian-batch-pvc -n yossarian-go --timeout=60s || echo "⚠️  Warning: Batch PVC not bound yet"

echo "🗄️  Deploying Database Service..."
kubectl apply -f 06-db-service-deployment.yaml

echo "🖥️  Deploying Main Application..."
kubectl apply -f 07-app-deployment.yaml

echo "🌐 Creating Ingress (HTTPProxy)..."
kubectl apply -f 08-httpproxy.yaml

if [ -f "09-certificate.yaml" ]; then
    echo "🔒 Creating TLS Certificate..."
    kubectl apply -f 09-certificate.yaml
fi

echo "⏰ Creating CronJob..."
kubectl apply -f 10-cronjob-ad-sync.yaml

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📊 Checking status..."
kubectl get all -n yossarian-go
echo ""
kubectl get pvc -n yossarian-go
echo ""

# Wait for pods to be ready
echo "⏳ Waiting for pods to be ready (this may take a minute)..."
kubectl wait --for=condition=Ready pod -l app=yossarian-go -n yossarian-go --timeout=120s || echo "⚠️  Warning: App pods not ready yet"
kubectl wait --for=condition=Ready pod -l app=yossarian-db-service -n yossarian-go --timeout=120s || echo "⚠️  Warning: DB service pod not ready yet"

echo ""
echo "🎉 Deployment successful!"
echo ""
echo "🔍 Next steps:"
echo "  1. Check logs: kubectl logs -n yossarian-go -l app=yossarian-go --tail=50"
echo "  2. Port-forward: kubectl port-forward -n yossarian-go svc/yossarian-go-service 8080:80"
echo "  3. Access: http://localhost:8080"
echo "  4. Test health: curl http://localhost:8080/health"
echo ""
echo "📚 See README.md for full documentation"
