#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$names = @('ConvertTo-NativeArgument','Invoke-PythonCommand','Stop-ChildProcess',
    'New-IsoLookup','Save-Report','Write-Log','Test-Cancellation','ConvertTo-SisouPath',
    'Initialize-Cancellation','Write-JsonAtomic')
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions $names
Initialize-Cancellation
[Console]::remove_CancelKeyPress($Script:CancelHandler)
$Script:CancellationRequested = $false
$Script:LogFilePath = $null
$LogLevel = 'ERROR'
$Script:ActiveProc = $null
$unstarted = New-Object System.Diagnostics.Process
try { Stop-ChildProcess $unstarted } finally { $unstarted.Dispose() }
$shell = (Get-Command powershell.exe).Source
$result = Invoke-PythonCommand $shell @('-NoProfile','-Command',
    "[Console]::Out.Write(('x' * 200000)); [Console]::Error.Write(('y' * 200000))") 20000
if ($result.ExitCode -ne 0 -or $result.StdOut.Length -ne 200000 -or $result.StdErr.Length -lt 200000) {
    throw "Large redirected output failed: exit=$($result.ExitCode), stdout=$($result.StdOut.Length), stderr=$($result.StdErr.Length)"
}
$quoted = ConvertTo-NativeArgument 'C:\directory with spaces\'
if ($quoted -ne '"C:\directory with spaces\\"') { throw 'Trailing backslash quoting failed.' }
if (-not [IO.Path]::IsPathRooted((ConvertTo-SisouPath '.\sisou.toml'))) {
    throw 'Relative SISOU config was not resolved before launch.'
}
$result = Invoke-PythonCommand $shell @('-NoProfile','-Command','Start-Sleep -Seconds 30') 500
if ($result.ExitCode -ne -2) { throw "Child timeout failed: $($result.ExitCode): $($result.StdErr)" }
[SisouCancellation]::Requested = $true
$result = Invoke-PythonCommand $shell @('-NoProfile','-Command','Start-Sleep -Seconds 30') 20000
if (-not $Script:CancellationRequested -or $result.ExitCode -ne -1) {
    throw 'Native cancellation flag did not stop the child.'
}
[SisouCancellation]::Requested = $false
$Script:CancellationRequested = $false
$lookup = New-IsoLookup @(@{key='F:\one\same.iso';name='same.iso'},
    @{key='F:\two\same.iso';name='same.iso'})
if ($lookup.Count -ne 2) { throw 'Duplicate filename identities collapsed.' }
$Script:ReportPath = Join-Path $PSScriptRoot ('sisou-report-test-' + [guid]::NewGuid() + '.json')
try {
    $report = @{completed=$null;cancelled=$false;cancelReason=$null;
        isos=@(@{key='F:\private\same.iso';name='same.iso'});
        sisou=@{logfile='C:\private\sisou.log';args=@('secret');stderr_tail='C:\Users\private'}}
    Save-Report $report
    $json = Get-Content -LiteralPath $Script:ReportPath -Raw
    if ($json -match 'private|secret|stderr_tail|"key"') { throw 'Private report data leaked.' }
} finally { Remove-Item -LiteralPath $Script:ReportPath -ErrorAction SilentlyContinue }
Write-Host '[OK] Runtime regression checks passed.'
