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
    $taskBuildOutput = 'dist\tbcrypt.exe'
    go build -trimpath -ldflags '-s -w' -o $taskBuildOutput ./cmd/tbcrypt
    if ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath $taskBuildOutput)) {
        Write-Warning 'Could not replace dist\tbcrypt.exe; trying dist\tbcrypt-new.exe (the old copy may be running).'
        $taskBuildOutput = 'dist\tbcrypt-new.exe'
        go build -trimpath -ldflags '-s -w' -o $taskBuildOutput ./cmd/tbcrypt
    }
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
    Write-Output "Built $taskBuildOutput"
} finally {
    if ($null -eq $taskPreviousCGO) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $taskPreviousCGO }
    Pop-Location
}
