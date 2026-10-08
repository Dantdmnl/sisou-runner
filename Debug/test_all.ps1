#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$shell = (Get-Process -Id $PID).Path
foreach ($test in @('test_syntax.ps1','test_integration.ps1','test_runtime.ps1','test_state.ps1','test_health.ps1','test_inputs.ps1','test_menu.ps1')) {
    Write-Host "Running $test..." -ForegroundColor Cyan
    & $shell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot $test)
    if ($LASTEXITCODE -ne 0) { throw "$test failed with exit code $LASTEXITCODE." }
}
Write-Host '[OK] All offline checks passed.' -ForegroundColor Green
