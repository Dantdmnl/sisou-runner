#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions @('Test-RunTimeout')
if (Test-RunTimeout 0 86400) { throw 'Unlimited batch was timed out.' }
if (Test-RunTimeout 3600 3599) { throw 'Batch was timed out before its explicit limit.' }
if (-not (Test-RunTimeout 3600 3600)) { throw 'Explicit limit was not enforced.' }
function Write-Log { param($Message,$Level) }
$guard = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -eq '$res.ExitCode -eq -2'
}, $true)
if (-not $guard) { throw 'Production timeout retry guard was not found.' }
$res = @{ExitCode=-2}
$finalResult = $null
$attempts = 0
foreach ($attempt in 1..2) {
    $attempts++
    . ([scriptblock]::Create($guard.Extent.Text))
}
if ($attempts -ne 1 -or $finalResult.ExitCode -ne -2) { throw 'Timed-out batch was retried.' }
$res = @{ExitCode=1}
$attempts = 0
foreach ($attempt in 1..2) {
    $attempts++
    . ([scriptblock]::Create($guard.Extent.Text))
}
if ($attempts -ne 2) { throw 'Timeout policy blocked ordinary retries.' }
Write-Host '[OK] Total-run timeout and retry policy checks passed.'
