$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & .\build.ps1
    if ($LASTEXITCODE -ne 0) { throw 'Build failed; nothing installed.' }
    $taskBuilt = @('dist\tbcrypt.exe', 'dist\tbcrypt-new.exe') |
        Where-Object { Test-Path -LiteralPath $_ } |
        Get-Item |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $taskBuilt) { throw 'No release executable was built.' }
    $taskInstallDir = Join-Path $env:LOCALAPPDATA 'Programs\tbcrypt'
    New-Item -ItemType Directory -Path $taskInstallDir -Force | Out-Null
    Copy-Item -LiteralPath $taskBuilt.FullName -Destination (Join-Path $taskInstallDir 'tbcrypt.exe') -Force
    $taskUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $taskEntries = @($taskUserPath -split ';' | Where-Object { $_.Trim() -ne '' })
    $taskAlreadyPresent = $false
    foreach ($taskEntry in $taskEntries) {
        $taskExpanded = [Environment]::ExpandEnvironmentVariables($taskEntry.Trim().Trim('"')).TrimEnd('\')
        if ([string]::Equals($taskExpanded, $taskInstallDir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            $taskAlreadyPresent = $true
            break
        }
    }
    if (-not $taskAlreadyPresent) {
        [Environment]::SetEnvironmentVariable('Path', (($taskEntries + $taskInstallDir) -join ';'), 'User')
    }
    Write-Output 'Open a new terminal and run: tbcrypt'
} finally {
    Pop-Location
}
