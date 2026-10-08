#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions @('Assert-Inputs','Test-IsVentoy')
$LogLevel = 'INFO'
$ConfigFile = $null
$LogDir = $null
$RetryCount = 2
$TimeoutSeconds = 3600
$HashThrottle = 4
$IsoScanDepth = -1
# Simulate an accessible drive without inspecting any actual USB drive.
function Test-Path { param($Path) return $true }
function Get-VentoyCandidates { return @('F:') }
foreach ($inputDrive in @('F','F:','F:\')) {
    $script:Drive = $inputDrive
    Assert-Inputs
    if ($script:Drive -ne 'F:') { throw "Drive shorthand was not normalized: $inputDrive" }
    if (-not (Test-IsVentoy $inputDrive)) { throw "Manual drive shorthand was rejected: $inputDrive" }
}
Write-Host '[OK] Drive input contract checks passed.'
