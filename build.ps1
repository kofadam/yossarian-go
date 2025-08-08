# Yossarian Go Build Script for Windows

param(
    [string]$Version = "v0.7.0"
)

# Get build time and git commit
$BuildTime = Get-Date -Format "yyyy-MM-dd_HH:mm:ss" -AsUTC
try {
    $GitCommit = (git rev-parse --short HEAD 2>$null)
    if (-not $GitCommit) { $GitCommit = "unknown" }
} catch {
    $GitCommit = "unknown"
}

Write-Host "Building Yossarian Go $Version" -ForegroundColor Green
Write-Host "Build Time: $BuildTime"
Write-Host "Git Commit: $GitCommit"

# Build Docker image with version info
$buildArgs = @(
    "build",
    "--build-arg", "VERSION=$Version",
    "--build-arg", "BUILD_TIME=$BuildTime",
    "--build-arg", "GIT_COMMIT=$GitCommit",
    "-t", "yossarian-go/yossarian-go:$Version",
    "-t", "yossarian-go/yossarian-go:latest",
    "."
)

docker $buildArgs

Write-Host "`nTagged as:" -ForegroundColor Green
Write-Host "  - yossarian-go/yossarian-go:$Version" -ForegroundColor Yellow
Write-Host "  - yossarian-go/yossarian-go:latest" -ForegroundColor Yellow