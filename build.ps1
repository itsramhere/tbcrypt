$ErrorActionPreference = 'Stop'
$taskPreviousCGO = $env:CGO_ENABLED
Push-Location $PSScriptRoot
try {
    $env:CGO_ENABLED = '0'
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'go test failed' }
    New-Item -ItemType Directory -Path dist -Force | Out-Null
    go build -trimpath -ldflags '-s -w -H=windowsgui' -o dist\tbcrypt.exe ./cmd/tbcrypt
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
} finally {
    if ($null -eq $taskPreviousCGO) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $taskPreviousCGO }
    Pop-Location
}
