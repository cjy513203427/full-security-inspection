#Requires -Version 5.1
# Builds NetWatch CookieGuard. Run from the project root:
#   .\build.ps1
$ErrorActionPreference = "Stop"

$goCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCmd) {
    $goCmd = "C:\Program Files\Go\bin\go.exe"
    if (-not (Test-Path $goCmd)) {
        throw "go.exe not found. Install Go from https://go.dev/dl/ or via 'winget install GoLang.Go'."
    }
} else {
    $goCmd = $goCmd.Source
}

New-Item -ItemType Directory -Force -Path build | Out-Null

Write-Host "==> go vet"
& $goCmd vet ./...
if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

Write-Host "==> go test"
& $goCmd test ./...
if ($LASTEXITCODE -ne 0) { throw "go test failed" }

# The "production" build tag is required by Wails itself (see
# github.com/wailsapp/wails/v2/internal/app/app_default_windows.go) — a
# plain `go build` without it compiles fine but pops a "Wails applications
# will not build without the correct build tags" error window at runtime
# instead of the real app. "debug" is additive (keeps default log
# verbosity higher); it's not required, just nice for the console build.
Write-Host "==> building release exe (no console window): build\netwatch.exe"
& $goCmd build -tags production -ldflags "-H=windowsgui -s -w" -o build\netwatch.exe .\cmd\netwatch
if ($LASTEXITCODE -ne 0) { throw "release build failed" }

Write-Host "==> building debug exe (console + live log output): build\netwatch-debug.exe"
& $goCmd build -tags "production debug" -o build\netwatch-debug.exe .\cmd\netwatch
if ($LASTEXITCODE -ne 0) { throw "debug build failed" }

Write-Host ""
Write-Host "Done."
Write-Host "  build\netwatch.exe        - daily use (tray icon only, logs to data dir\netwatch.log)"
Write-Host "  build\netwatch-debug.exe  - first run / troubleshooting (keeps a console window)"
