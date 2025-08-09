#!/bin/bash
VERSION=${1:-v0.8.8}

echo "Building DB Service ${VERSION}"
docker build -f Dockerfile.db-service -t yossarian-go-db-service:${VERSION} -t yossarian-go-db-service:latest .