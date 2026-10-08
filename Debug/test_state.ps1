#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions @('Write-JsonAtomic','Enter-RunnerLock','Assert-ConfigValues')
$testRoot = Join-Path $PSScriptRoot ('sisou-state-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
$runLock = $null
$blockedFile = $null
try {
    $path = Join-Path $testRoot 'state.json'
    Write-JsonAtomic -Path $path -Value @{stage='before'}
    Write-JsonAtomic -Path $path -Value @{stage='after'}
    if ((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).stage -ne 'after') {
        throw 'Atomic replacement did not publish the new state.'
    }
    $blockedFile = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    $failed = $false
    try { Write-JsonAtomic -Path $path -Value @{stage='broken'} } catch { $failed = $true }
    $blockedFile.Dispose(); $blockedFile = $null
    if (-not $failed -or (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).stage -ne 'after') {
        throw 'Failed replacement damaged the previous state.'
    }
    if (@(Get-ChildItem -LiteralPath $testRoot -Filter '*.tmp').Count -ne 0) { throw 'Staging file leaked.' }
    $runLock = Enter-RunnerLock $testRoot
    $failed = $false
    try { $otherLock = Enter-RunnerLock $testRoot; $otherLock.Dispose() } catch { $failed = $true }
    if (-not $failed) { throw 'Concurrent runtime lock succeeded.' }
    $runLock.Dispose(); $runLock = $null
    $runLock = Enter-RunnerLock $testRoot
    Assert-ConfigValues @{DryRun=$false;RetryCount=2;IncludeIsoPattern=@('*.iso');LogLevel='INFO'}
    foreach ($invalid in @(@{DryRun='false'}, @{RetryCount=1.5}, @{TimeoutSeconds=0},
        @{IncludeIsoPattern=@('*.iso',2)}, @{LogLevel='verbose'}, @{Drive=$null})) {
        $failed = $false
        try { Assert-ConfigValues $invalid } catch { $failed = $true }
        if (-not $failed) { throw 'Invalid runner config was accepted.' }
    }
} finally {
    if ($blockedFile) { $blockedFile.Dispose() }
    if ($runLock) { $runLock.Dispose() }
    # Only the unique directory created by this test is removed.
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
Write-Host '[OK] State, lock, and config regression checks passed.'
