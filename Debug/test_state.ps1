#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions @('Write-JsonAtomic','Enter-RunnerLock','Assert-ConfigValues','Save-RunnerSettings','Resolve-RunnerSettingsPath','Set-DefaultFromConfig')
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
    Assert-ConfigValues @{DryRun=$false;RetryCount=2;TimeoutSeconds=0;IncludeIsoPattern=@('*.iso');LogLevel='INFO'}
    foreach ($invalid in @(@{DryRun='false'}, @{RetryCount=1.5}, @{TimeoutSeconds=1},
        @{IncludeIsoPattern=@('*.iso',2)}, @{LogLevel='verbose'}, @{Drive=$null})) {
        $failed = $false
        try { Assert-ConfigValues $invalid } catch { $failed = $true }
        if (-not $failed) { throw 'Invalid runner config was accepted.' }
    }
    $script:SettingsSavePath = Resolve-RunnerSettingsPath $testRoot $null
    Write-JsonAtomic -Path $script:SettingsSavePath -Value @{IncludeIsoPattern=@('ubuntu*.iso');HashThrottle=7}
    $TimeoutSeconds = 7200
    $RetryCount = 3
    $VerifyHashes = $true
    $ValidateIsoHeaders = $false
    $SkipPipUpgrade = $true
    $SkipGpgCheck = $false
    $null = Save-RunnerSettings
    $saved = Get-Content -LiteralPath $script:SettingsSavePath -Raw | ConvertFrom-Json
    if ($saved.TimeoutSeconds -ne 7200 -or -not $saved.VerifyHashes -or $saved.HashThrottle -ne 7 -or
        $saved.IncludeIsoPattern[0] -ne 'ubuntu*.iso') { throw 'Settings failed to persist or unrelated options were lost.' }
    $script:CliBoundParameters = @{TimeoutSeconds=$true}
    $script:AppliedTimeout = -1
    Set-DefaultFromConfig @{TimeoutSeconds=7200} 'TimeoutSeconds' { param($v) $script:AppliedTimeout=$v }
    if ($script:AppliedTimeout -ne -1) { throw 'Saved settings overrode an explicit CLI value.' }
    $script:CliBoundParameters = @{}
    Set-DefaultFromConfig @{TimeoutSeconds=7200} 'TimeoutSeconds' { param($v) $script:AppliedTimeout=$v }
    if ($script:AppliedTimeout -ne 7200) { throw 'Saved settings were not applied as defaults.' }
} finally {
    if ($blockedFile) { $blockedFile.Dispose() }
    if ($runLock) { $runLock.Dispose() }
    # Only the unique directory created by this test is removed.
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
Write-Host '[OK] State, lock, and config regression checks passed.'
