# Yossarian Go - Helm Charts

Official Helm charts for deploying Yossarian Go to Kubernetes.

## 📦 Available Charts

### yossarian-go
Enterprise-grade log sanitization system with pattern detection and batch processing.

**Latest Version:** 0.13.8  
**App Version:** v0.13.8  
**Status:** Production Ready

**Quick Install:**
```bash
helm install yossarian oci://ghcr.io/kofadam/charts/yossarian-go \
  --version 0.13.8 \
  --namespace yossarian-go \
  --create-namespace
```

**Documentation:** [yossarian-go/README.md](./yossarian-go/README.md)  
**Changelog:** [yossarian-go/CHANGELOG.md](./yossarian-go/CHANGELOG.md)

---

## 🚀 Installation

### From OCI Registry (Recommended)

```bash
helm install yossarian oci://ghcr.io/kofadam/charts/yossarian-go \
  --version 0.13.8 \
  -n yossarian-go --create-namespace
```

### From Local Chart

```bash
helm install yossarian ./yossarian-go \
  -n yossarian-go --create-namespace
```

### Air-Gap Installation

See [Distribution Tooling Guide](../docs/DISTRIBUTION-TOOLING-GUIDE.md)

---

## 📋 Version History

| Chart Version | App Version | Release Date | Notes |
|---------------|-------------|--------------|-------|
| 0.13.8 | v0.13.8 | 2026-01-12 | ServiceMonitor, air-gap support, certificate fixes |
| 0.13.3 | v0.13.3 | 2026-01-06 | Initial release |

---

## 🔗 Links

- **GitHub Repository:** https://github.com/kofadam/yossarian-go
- **Documentation:** https://github.com/kofadam/yossarian-go/tree/main/docs
- **Issues:** https://github.com/kofadam/yossarian-go/issues
- **Releases:** https://github.com/kofadam/yossarian-go/releases

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md).

## 📄 License

MIT License - see [LICENSE](../LICENSE) for details.
