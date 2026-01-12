# Distribution Tooling for Helm (dt4h) Support

## 🎯 What is Distribution Tooling for Helm?

**Distribution Tooling for Helm (dt4h)** is a VMware Labs project that enables:

✅ **Air-gap deployments** - Bundle all container images with the Helm chart  
✅ **Registry relocation** - Automatically rewrite image references  
✅ **Simplified distribution** - Single artifact contains chart + images  
✅ **Vendor independence** - Works with any OCI-compliant registry

**Project:** https://github.com/vmware-labs/distribution-tooling-for-helm

## 📋 Chart Annotations Added

### Chart.yaml - New Annotations

```yaml
annotations:
  # Primary DT4H annotation (replaces old "images" annotation)
  distribution.carto.run/images: |
    - name: yossarian-go
      image: ghcr.io/kofadam/yossarian-go:v0.13.8
      whitelisted: true
    - name: yossarian-go-db-service
      image: ghcr.io/kofadam/yossarian-go-db-service:v0.12.3
      whitelisted: true
    - name: minio
      image: quay.io/minio/minio:RELEASE.2024-01-01T00-00-00Z
      whitelisted: true
    - name: curl
      image: curlimages/curl:8.5.0
      whitelisted: true
  
  # Legacy annotation kept for backwards compatibility
  images: |
    - name: yossarian-go
      image: ghcr.io/kofadam/yossarian-go:v0.13.8
    # ... etc
```

**Key changes:**
1. ✅ Added `distribution.carto.run/images` annotation (DT4H standard)
2. ✅ Kept legacy `images` annotation for backwards compatibility
3. ✅ Added `whitelisted: true` flag for all images
4. ✅ Changed from `:latest` tags to **specific versions** (required for air-gap)

## 🚀 Usage Examples

### 1. Basic Wrapping (Bundle Images)

```bash
# Install Distribution Tooling
curl -L https://github.com/vmware-labs/distribution-tooling-for-helm/releases/latest/download/dt-linux-amd64.tar.gz | tar xz
sudo mv dt /usr/local/bin/

# Wrap the chart with all images
dt wrap oci://ghcr.io/kofadam/yossarian-go:0.13.8 \
  --output-dir ./wrapped-charts

# Result: yossarian-go-0.13.8.wrap.tgz (chart + 4 container images)
```

### 2. Push to Air-Gap Registry

```bash
# Push wrapped chart to your internal registry
dt push ./wrapped-charts/yossarian-go-0.13.8.wrap.tgz \
  --to-registry registry.company.internal \
  --to-repository yossarian-go

# Images will be automatically relocated to:
# - registry.company.internal/yossarian-go/yossarian-go:v0.13.8
# - registry.company.internal/yossarian-go/yossarian-go-db-service:v0.12.3
# - registry.company.internal/yossarian-go/minio:RELEASE.2024-01-01T00-00-00Z
# - registry.company.internal/yossarian-go/curl:8.5.0
```

### 3. Install from Air-Gap Registry

```bash
# Install with automatic image relocation
helm install yossarian oci://registry.company.internal/yossarian-go \
  --version 0.13.8 \
  -n yossarian-go --create-namespace \
  --set ingress.host=yossarian.company.com
```

**No values.yaml changes needed!** The chart automatically uses relocated images.

### 4. Manual Image Relocation (Alternative)

If you prefer manual control:

```bash
# Pull and push images manually
docker pull ghcr.io/kofadam/yossarian-go:v0.13.8
docker tag ghcr.io/kofadam/yossarian-go:v0.13.8 registry.company.internal/yossarian-go:v0.13.8
docker push registry.company.internal/yossarian-go:v0.13.8

# Repeat for all 4 images...

# Override image locations in values.yaml
helm install yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.8 \
  --set images.app.repository=registry.company.internal/yossarian-go \
  --set images.app.tag=v0.13.8 \
  --set images.database.repository=registry.company.internal/yossarian-go-db-service \
  --set images.database.tag=v0.12.3 \
  # ... etc
```

## 📦 Chart Structure with DT4H

```
yossarian-go-0.13.8.wrap.tgz
├── Chart.yaml (with distribution.carto.run/images annotation)
├── values.yaml
├── templates/
│   ├── frontend.yaml
│   ├── worker.yaml
│   ├── database.yaml
│   ├── minio.yaml
│   └── ...
└── .images/
    ├── yossarian-go-v0.13.8.tar (container image)
    ├── yossarian-go-db-service-v0.12.3.tar
    ├── minio-RELEASE.2024-01-01T00-00-00Z.tar
    └── curl-8.5.0.tar
```

## ✅ Benefits

### For Users
- ✅ **Single artifact** - Download once, contains everything
- ✅ **Air-gap friendly** - No internet required during installation
- ✅ **Automatic relocation** - Images work with any registry
- ✅ **Verified images** - All images tested together
- ✅ **Simplified upgrades** - Consistent versions across components

### For Operators
- ✅ **Compliance** - Control image sources and versions
- ✅ **Security scanning** - Scan all images before deployment
- ✅ **Bandwidth savings** - Transfer once, deploy many times
- ✅ **Version control** - Exact reproducibility

### For Vendors (You!)
- ✅ **Standardized distribution** - Industry best practice
- ✅ **Enterprise readiness** - Meet air-gap requirements
- ✅ **Reduced support** - Fewer "image not found" issues
- ✅ **Better testing** - Validate entire bundle

## 🔍 Verification

### Check Annotations
```bash
# Extract and view annotations
helm show chart oci://ghcr.io/kofadam/yossarian-go:0.13.8 | grep -A 20 "annotations:"

# Should show distribution.carto.run/images with all 4 images
```

### Verify Image Versions
```bash
# Check what images will be pulled
helm template yossarian oci://ghcr.io/kofadam/yossarian-go:0.13.8 | \
  grep "image:" | sort -u

# Should show:
# - ghcr.io/kofadam/yossarian-go:v0.13.8
# - ghcr.io/kofadam/yossarian-go-db-service:v0.12.3
# - quay.io/minio/minio:RELEASE.2024-01-01T00-00-00Z
# - curlimages/curl:8.5.0
```

### Test Wrapped Chart
```bash
# Verify wrapped chart structure
tar -tzf yossarian-go-0.13.8.wrap.tgz | head -20

# Should show .images/ directory with 4 .tar files
```

## 📚 Additional Resources

- **DT4H Documentation:** https://github.com/vmware-labs/distribution-tooling-for-helm
- **Helm OCI Support:** https://helm.sh/docs/topics/registries/
- **Air-Gap Best Practices:** https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/air-gapped/

## 🔧 Troubleshooting

### Issue: "No such annotation: distribution.carto.run/images"
**Solution:** Use Helm 3.8+ and DT4H v0.2.0+

### Issue: "Image pull error in air-gap"
**Solution:** Verify registry credentials and image names match relocated paths

### Issue: "Wrapped chart too large"
**Solution:** Normal! Chart with images is ~500MB vs ~50KB without images

### Issue: "Can I use this without DT4H?"
**Solution:** Yes! The chart works normally without DT4H. The annotations are optional.

## 🎯 Migration Path

### From v0.13.3 (without DT4H) → v0.13.8 (with DT4H)

**Option 1: Standard upgrade (no air-gap)**
```bash
# No changes needed - works exactly as before
helm upgrade yossarian oci://ghcr.io/kofadam/yossarian-go \
  --version 0.13.8 \
  -n yossarian-go
```

**Option 2: Switch to air-gap distribution**
```bash
# Wrap chart with images
dt wrap oci://ghcr.io/kofadam/yossarian-go:0.13.8 -o ./wrapped

# Push to air-gap registry
dt push ./wrapped/yossarian-go-0.13.8.wrap.tgz \
  --to-registry registry.company.internal

# Install from air-gap registry
helm install yossarian oci://registry.company.internal/yossarian-go \
  --version 0.13.8 \
  -n yossarian-go-new
```

## ✅ Summary

The Yossarian Go Helm chart **now fully supports Distribution Tooling for Helm**:

1. ✅ Added `distribution.carto.run/images` annotation
2. ✅ Specified exact image versions (no `:latest` tags)
3. ✅ Whitelisted all images for relocation
4. ✅ Documented air-gap installation process
5. ✅ Backwards compatible with standard Helm workflow

**This makes Yossarian Go ready for enterprise air-gap deployments! 🚀**

---

**Chart Version:** 0.13.8  
**DT4H Support:** Full  
**Backwards Compatible:** Yes  
**Air-Gap Ready:** Yes ✅
