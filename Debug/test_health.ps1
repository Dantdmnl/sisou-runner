#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions @('Test-SisouRuntime')
function Write-Log { param($Message,$Level) }
function Invoke-PythonCommand {
    param($PythonExe,$Arguments,$TimeoutMs)
    if ($Arguments[0] -eq '-c') {
        return @{ExitCode=0;StdOut='{"sisouVersion":"2.3.0"}';StdErr=''}
    }
    return @{ExitCode=$script:DependencyExit;StdOut='Dependency result';StdErr=''}
}
$script:DependencyExit = 0
$result = Test-SisouRuntime 'test-python'
if (-not $result.Success -or $result.Version -ne '2.3.0') { throw 'Healthy runtime metadata was lost.' }
$script:DependencyExit = 1
$result = Test-SisouRuntime 'test-python'
if ($result.Success -or $result.Message -notmatch 'Dependency result') {
    throw 'Inconsistent dependency environment was accepted.'
}
Write-Host '[OK] Runtime health contract checks passed.'
