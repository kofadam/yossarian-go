@echo off
setlocal enabledelayedexpansion

:: Get version from argument or use default
if "%1"=="" (
    set VERSION=v0.7.0
) else (
    set VERSION=%1
)

:: Get current date and time
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set BUILD_TIME=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%_%datetime:~8,2%:%datetime:~10,2%:%datetime:~12,2%

:: Get git commit
for /f "delims=" %%I in ('git rev-parse --short HEAD 2^>nul') do set GIT_COMMIT=%%I
if "%GIT_COMMIT%"=="" set GIT_COMMIT=unknown

echo Building Yossarian Go %VERSION%
echo Build Time: %BUILD_TIME%
echo Git Commit: %GIT_COMMIT%

:: Build Docker image
docker build ^
  --build-arg VERSION=%VERSION% ^
  --build-arg BUILD_TIME=%BUILD_TIME% ^
  --build-arg GIT_COMMIT=%GIT_COMMIT% ^
  -t yossarian-go/yossarian-go:%VERSION% ^
  -t yossarian-go/yossarian-go:latest ^
  .

echo.
echo Tagged as:
echo   - yossarian-go/yossarian-go:%VERSION%
echo   - yossarian-go/yossarian-go:latest   