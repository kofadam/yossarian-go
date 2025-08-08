#!/bin/bash

# Get version from argument or use default
VERSION=${1:-v0.7.0}
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Building Yossarian Go ${VERSION}"
echo "Build Time: ${BUILD_TIME}"
echo "Git Commit: ${GIT_COMMIT}"

# Build Docker image with version info
docker build \
  --build-arg VERSION=${VERSION} \
  --build-arg BUILD_TIME=${BUILD_TIME} \
  --build-arg GIT_COMMIT=${GIT_COMMIT} \
  -t yossarian-go/yossarian-go:${VERSION} \
  -t yossarian-go/yossarian-go:latest \
  .

echo "Tagged as:"
echo "  - yossarian-go/yossarian-go:${VERSION}"
echo "  - yossarian-go/yossarian-go:latest"