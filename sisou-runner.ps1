# Version: 2.3

<#
.SYNOPSIS
    sisou-runner.ps1 - Wrapper for SuperISOUpdater (SISOU) on Ventoy drives.

.DESCRIPTION
    Locates or bootstraps a Python 3.12+ runtime, installs SISOU into it, auto-detects
    your Ventoy drive, runs sisou with retries and timeout, and writes a structured log
    and a privacy-safe JSON report. Handles Ctrl+C gracefully (kills the child process).

.PARAMETER Drive
    Ventoy drive letter (e.g. "E:"). Auto-detected when omitted.

.PARAMETER ConfigFile
    Path to a SISOU sisou.toml file. SISOU accepts this as its positional
    config_path argument instead of the Ventoy drive directory.

.PARAMETER AdvancedConfigFile
    Path to a sisou-runner JSON config file. Values act as defaults and are
    overridden by explicit command-line parameters.

.PARAMETER LogLevel
    SISOU log verbosity: DEBUG | INFO | WARNING | ERROR | CRITICAL (passed via -l).

.PARAMETER LogDir
    Directory for wrapper and SISOU log files. Default: %ProgramData%\SISOU\logs.

.PARAMETER RetryCount
    Total SISOU attempts on non-zero exit (default 2).

.PARAMETER TimeoutSeconds
    Per-attempt wall-clock timeout in seconds (default 3600).

.PARAMETER HashThrottle
    Parallel SHA-256 threads on PS 7+ when -VerifyHashes is active (default 4).

.PARAMETER IsoScanDepth
    Maximum folder depth to scan for ISO files. Default -1 scans the whole drive.

.PARAMETER IncludeIsoPattern
    Wildcard patterns for ISO filenames to include, such as ubuntu*.iso.

.PARAMETER ExcludeIsoPattern
    Wildcard patterns for ISO filenames to exclude, such as *beta*.iso.

.PARAMETER VerifyHashes
    Compute SHA-256 of every discovered ISO before and after the run. Opt-in
    because reading every byte of a large USB collection can be slow.

.PARAMETER ValidateIsoHeaders
    Check that discovered ISO files contain a readable ISO-9660 CD001 descriptor.

.PARAMETER SkipPipUpgrade
    Skip the "pip install --upgrade sisou" step. Use when offline or on a metered
    connection where sisou is already installed at the required version.

.PARAMETER InstallGpg
    Install GnuPG with winget if gpg.exe is missing.

.PARAMETER SkipGpgCheck
    Skip the GnuPG pre-flight check. SISOU may skip signature verification.

.PARAMETER DryRun
    Show what would be done without running sisou.

.PARAMETER NonInteractive
    No prompts. Use first Ventoy drive found, or exit 10 if none.

.PARAMETER UseWinget
    Ensure Python through winget, then use an isolated managed SISOU environment.

.PARAMETER Help
    Print usage and exit 0.

.PARAMETER Menu
    Open the interactive menu even when command-line defaults are supplied.

.PARAMETER SisouArgs
    Additional arguments forwarded to SISOU. Prefer the runner's LogLevel and
    LogDir options for logging so its status reporting uses the same log file.

.EXAMPLE
    pwsh -File sisou-runner.ps1
.EXAMPLE
    pwsh -File sisou-runner.ps1 -Drive F: -DryRun
.EXAMPLE
    pwsh -File sisou-runner.ps1 -NonInteractive -LogLevel DEBUG
.EXAMPLE
    pwsh -File sisou-runner.ps1 -Drive F: -SkipPipUpgrade

.NOTES
    Requires PowerShell 5.1+. Python 3.12+ is supported; the runner prefers the
    newest healthy interpreter. On PS 7+, -VerifyHashes hashing runs in parallel.

.EXIT CODES
    0   Success
   10   No Ventoy drive found / invalid selection
   20   Python runtime bootstrap failure
   30   SISOU process failure or logged updater errors
   40   Pre-flight validation failure
   50   Reserved installation failure code (current runtime failures return 20)
   60   Another runner is already active
   99   Unexpected / unhandled error
  130   Cancelled by user
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]  $Drive,
    [string]  $ConfigFile,
    [string]  $AdvancedConfigFile,
    [ValidateSet('DEBUG','INFO','WARNING','ERROR','CRITICAL')]
    [string]  $LogLevel,
    [string]  $LogDir,
    [int]     $RetryCount     = 2,
    [int]     $TimeoutSeconds = 3600,
    [int]     $HashThrottle   = 4,
    [int]     $IsoScanDepth   = -1,
    [string[]] $IncludeIsoPattern,
    [string[]] $ExcludeIsoPattern,
    [switch]  $VerifyHashes,
    [switch]  $ValidateIsoHeaders,
    [switch]  $SkipPipUpgrade,
    [switch]  $InstallGpg,
    [switch]  $SkipGpgCheck,
    [switch]  $DryRun,
    [switch]  $NonInteractive,
    [switch]  $UseWinget,
    [switch]  $Help,
    [switch]  $Menu,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $SisouArgs
)

$ScriptVersion = '2.3'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

###############################################################################
# CONSOLE APPEARANCE
# Force a black background so the script looks consistent regardless of whether
# the user opened a legacy blue PowerShell window or Windows Terminal.
###############################################################################
try {
    if ([Environment]::UserInteractive -and [Console]::BackgroundColor -ne [ConsoleColor]::Black) {
        [Console]::BackgroundColor = [ConsoleColor]::Black
        [Console]::Clear()
    }
} catch { }

###############################################################################
# DIRECT-LAUNCH DETECTION
# When sisou-runner.ps1 is launched via "Run with PowerShell" or by double-
# clicking, Windows spawns a transient console window that closes the moment
# the script exits. Detect this (parent == explorer.exe or OpenWith.exe, possibly
# via an intermediate conhost/svchost) and pause before every exit so the user
# can read the output. Walk up to 4 levels to handle Windows 11's OpenWith chain.
###############################################################################
$Script:PauseAtExit = $false
if (-not $NonInteractive -and [Environment]::UserInteractive) {
    try {
        $checkPid = $PID
        $levels   = 0
        $shellProcessNames = @('explorer','openwith','sihost')
        while ($levels -lt 4 -and $checkPid -gt 0) {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$checkPid" -ErrorAction Stop
            if (-not $proc) { break }
            $parentName = (Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue).ProcessName
            if ($parentName -and $shellProcessNames -contains $parentName.ToLower()) {
                $Script:PauseAtExit = $true; break
            }
            $checkPid = $proc.ParentProcessId
            $levels++
        }
    } catch { }
}

###############################################################################
# HELP
###############################################################################
function Write-HelpText {
    Write-Host @'
sisou-runner.ps1 - SuperISOUpdater (SISOU) wrapper
===================================================

USAGE
  pwsh -File sisou-runner.ps1 [OPTIONS] [-SisouArgs <args>]

OPTIONS
  -Drive <letter>         Ventoy drive letter. Auto-detected if omitted.
  -ConfigFile <path>      SISOU sisou.toml path used as config_path.
  -AdvancedConfigFile <p> sisou-runner JSON defaults file.
  -LogLevel <level>       SISOU log verbosity: DEBUG|INFO|WARNING|ERROR|CRITICAL.
  -LogDir <path>          Log directory (default: %ProgramData%\SISOU\logs).
  -RetryCount <n>         SISOU attempts on failure (default: 2).
  -TimeoutSeconds <n>     Per-attempt timeout in seconds (default: 3600).
  -HashThrottle <n>       Parallel SHA-256 threads on PS7+ with -VerifyHashes (default: 4).
  -IsoScanDepth <n>       Max folder depth for ISO scan; -1 scans all folders.
  -IncludeIsoPattern <p>  Wildcard ISO filename include filter(s).
  -ExcludeIsoPattern <p>  Wildcard ISO filename exclude filter(s).
  -VerifyHashes           SHA-256 each ISO before and after - opt-in, slow on USB.
  -ValidateIsoHeaders     Check ISO-9660 CD001 descriptors before running sisou.
  -SkipPipUpgrade         Skip SISOU upgrade in an existing managed environment.
  -InstallGpg             Install GnuPG with winget if gpg.exe is missing.
  -SkipGpgCheck           Skip GnuPG pre-flight; SISOU may skip signature checks.
  -DryRun                 Preview only; sisou is not executed.
  -NonInteractive         No prompts; fail fast if input is missing.
  -UseWinget              Ensure Python via winget; SISOU stays in a managed venv.
  -Help                   Show this help.
  -Menu                   Open the menu with supplied defaults; Enter previews.
  -SisouArgs <args>        Additional supported SISOU arguments.

EXIT CODES
   0  Success
  10  No Ventoy drive found
  20  Python runtime setup or health check failed
  30  SISOU process failed or logged updater errors
  40  Pre-flight validation failure
  50  Reserved installation failure code; runtime failures currently return 20
  60  Another runner is already active
  99  Unexpected error
 130  Cancelled by user

SISOU KNOWN LIMITATIONS
  - Non-zero SISOU process exits may be retried. Logged updater errors with a
    zero process exit are reported as partial failures without an automatic retry.
  - Microsoft Windows ISOs require accepting Microsoft's EULA interactively;
    the Windows11 updater is blocked by Microsoft Sentinel in some regions.
  - ShredOS version strings use a non-numeric scheme; sisou cannot compare them.
  - UBCD (UltimateBootCD) may fail if ultimatebootcd.com is unreachable.
  - Fedora version detection can break when getfedora.org changes its page layout.
  - sisou only manages ISOs it knows about; unknown or custom ISOs are untouched.
  - No proxy support in sisou itself; set HTTPS_PROXY in your environment if needed.
'@
}

if ($Help) {
    Write-HelpText
    if ($Script:PauseAtExit) {
        Write-Host ''
        Write-Host 'Press Enter to close this window...' -ForegroundColor DarkGray
        $null = Read-Host
    }
    exit 0
}

###############################################################################
# SCRIPT-SCOPE STATE
###############################################################################
$Script:BaseDir     = Join-Path $env:ProgramData 'SISOU'
$Script:LogDir      = if ($PSBoundParameters.ContainsKey('LogDir') -and
                          -not [string]::IsNullOrWhiteSpace($LogDir)) {
                          $LogDir
                      } else {
                          Join-Path $Script:BaseDir 'logs'
                      }
$Script:ReportPath  = Join-Path $Script:BaseDir 'report.json'
$Script:StateFile   = Join-Path $Script:BaseDir 'state.json'
$Script:LogFilePath = $null   # set by Initialize-Logging
$Script:DryRun      = [bool]$DryRun
$Script:ActiveProc  = $null   # tracked for Ctrl+C cleanup
$Script:RunLock     = $null
$Script:FromMenu    = $false  # true when user picked an option from the launch menu
$Script:SelectedVentoyRoot = $null
$Script:GpgExe      = $null
$Script:CancellationRequested = $false
$Script:CancellationReason = $null
$Script:CliBoundParameters = @{}
foreach ($key in $PSBoundParameters.Keys) { $Script:CliBoundParameters[$key] = $true }

###############################################################################
# ADVANCED RUNNER CONFIG
# JSON values are defaults only. Explicit command-line parameters always win.
###############################################################################
function Set-DefaultFromConfig {
    param(
        [hashtable] $ConfigValues,
        [string]    $Name,
        [scriptblock] $Setter
    )
    if (-not $ConfigValues.ContainsKey($Name)) { return }
    if ($Script:CliBoundParameters.ContainsKey($Name)) { return }
    & $Setter $ConfigValues[$Name]
}

function Read-AdvancedConfig {
    param([string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return @{} }
    if (-not (Test-Path $Path)) {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: Advanced config file not found.' -ForegroundColor Red
        Write-Host "  Path supplied: '$Path'" -ForegroundColor Yellow
        exit 40
    }

    try {
        $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($json -isnot [System.Management.Automation.PSCustomObject]) {
            throw 'Runner config must be a JSON object.'
        }
        $values = @{}
        foreach ($prop in $json.PSObject.Properties) { $values[$prop.Name] = $prop.Value }
        Assert-ConfigValues -Values $values
        return $values
    } catch {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: Advanced config file is invalid.' -ForegroundColor Red
        Write-Host "  Path   : '$Path'" -ForegroundColor Yellow
        Write-Host "  Reason : $_" -ForegroundColor Yellow
        exit 40
    }
}

function Assert-ConfigValues {
    param([hashtable] $Values)
    $switchNames = @('VerifyHashes','ValidateIsoHeaders','SkipPipUpgrade','InstallGpg',
        'SkipGpgCheck','DryRun','NonInteractive','UseWinget')
    $minimums = @{ RetryCount=1; TimeoutSeconds=30; HashThrottle=1; IsoScanDepth=-1 }
    foreach ($key in $Values.Keys) {
        $value = $Values[$key]
        if ($switchNames -contains $key -and $value -isnot [bool]) {
            throw "$key must be a JSON boolean (true or false)."
        }
        if ($minimums.ContainsKey($key)) {
            if (($value -isnot [int] -and $value -isnot [long]) -or
                $value -lt $minimums[$key] -or $value -gt [int]::MaxValue) {
                throw "$key must be an integer between $($minimums[$key]) and $([int]::MaxValue)."
            }
        }
        if (@('Drive','ConfigFile','LogDir','LogLevel') -contains $key -and $value -isnot [string]) {
            throw "$key must be a string."
        }
        if (@('IncludeIsoPattern','ExcludeIsoPattern','SisouArgs') -contains $key) {
            if ($value -isnot [array] -and $value -isnot [string]) { throw "$key must be a string or string array." }
            foreach ($item in @($value)) {
                if ($item -isnot [string]) { throw "$key must contain only strings." }
            }
        }
        if ($key -eq 'LogLevel' -and @('DEBUG','INFO','WARNING','ERROR','CRITICAL') -notcontains $value) {
            throw 'LogLevel must be DEBUG, INFO, WARNING, ERROR, or CRITICAL.'
        }
    }
}

function Set-AdvancedConfigDefaults {
    if ([string]::IsNullOrWhiteSpace($AdvancedConfigFile)) { return }

    $cfg = Read-AdvancedConfig -Path $AdvancedConfigFile
    if ($cfg.Count -eq 0) { return }

    $allowed = @(
        'Drive','ConfigFile','LogLevel','LogDir','RetryCount','TimeoutSeconds',
        'HashThrottle','IsoScanDepth','IncludeIsoPattern','ExcludeIsoPattern',
        'VerifyHashes','ValidateIsoHeaders','SkipPipUpgrade','InstallGpg',
        'SkipGpgCheck','DryRun',
        'NonInteractive','UseWinget','SisouArgs'
    )
    foreach ($key in $cfg.Keys) {
        if ($allowed -notcontains $key) {
            Write-Host "WARNING: Ignoring unknown advanced config option '$key'." -ForegroundColor Yellow
        }
    }

    Set-DefaultFromConfig $cfg 'Drive'             { param($v) $script:Drive = [string]$v }
    Set-DefaultFromConfig $cfg 'ConfigFile'        { param($v) $script:ConfigFile = [string]$v }
    Set-DefaultFromConfig $cfg 'LogLevel'          { param($v) $script:LogLevel = [string]$v }
    Set-DefaultFromConfig $cfg 'LogDir'            { param($v) $script:LogDir = [string]$v }
    Set-DefaultFromConfig $cfg 'RetryCount'        { param($v) $script:RetryCount = [int]$v }
    Set-DefaultFromConfig $cfg 'TimeoutSeconds'    { param($v) $script:TimeoutSeconds = [int]$v }
    Set-DefaultFromConfig $cfg 'HashThrottle'      { param($v) $script:HashThrottle = [int]$v }
    Set-DefaultFromConfig $cfg 'IsoScanDepth'      { param($v) $script:IsoScanDepth = [int]$v }
    Set-DefaultFromConfig $cfg 'IncludeIsoPattern' { param($v) $script:IncludeIsoPattern = @($v) }
    Set-DefaultFromConfig $cfg 'ExcludeIsoPattern' { param($v) $script:ExcludeIsoPattern = @($v) }
    Set-DefaultFromConfig $cfg 'VerifyHashes'      { param($v) $script:VerifyHashes = [bool]$v }
    Set-DefaultFromConfig $cfg 'ValidateIsoHeaders' { param($v) $script:ValidateIsoHeaders = [bool]$v }
    Set-DefaultFromConfig $cfg 'SkipPipUpgrade'    { param($v) $script:SkipPipUpgrade = [bool]$v }
    Set-DefaultFromConfig $cfg 'InstallGpg'        { param($v) $script:InstallGpg = [bool]$v }
    Set-DefaultFromConfig $cfg 'SkipGpgCheck'      { param($v) $script:SkipGpgCheck = [bool]$v }
    Set-DefaultFromConfig $cfg 'DryRun'            { param($v) $script:DryRun = [bool]$v }
    Set-DefaultFromConfig $cfg 'NonInteractive'    { param($v) $script:NonInteractive = [bool]$v }
    Set-DefaultFromConfig $cfg 'UseWinget'         { param($v) $script:UseWinget = [bool]$v }
    Set-DefaultFromConfig $cfg 'SisouArgs'         { param($v) $script:SisouArgs = @($v) }

    $Script:LogDir = if (-not [string]::IsNullOrWhiteSpace($LogDir)) {
        $LogDir
    } else {
        Join-Path $Script:BaseDir 'logs'
    }
    $Script:DryRun = [bool]$DryRun
}

Set-AdvancedConfigDefaults

###############################################################################
# CTRL+C / SIGINT HANDLER
# Registered once at startup. Kills any in-flight child process cleanly.
###############################################################################
# ConsoleCancelEventHandler - fires before the process exits on Ctrl+C
function Initialize-Cancellation {
try { [Console]::TreatControlCAsInput = $false } catch { }
if (-not ('SisouCancellation' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
public static class SisouCancellation {
    public static volatile bool Requested;
    public static void OnCancel(object sender, ConsoleCancelEventArgs args) {
        args.Cancel = true;
        Requested = true;
    }
}
'@
}
[SisouCancellation]::Requested = $false
$Script:CancelHandler = [Delegate]::CreateDelegate([ConsoleCancelEventHandler],
    [SisouCancellation].GetMethod('OnCancel'))
[Console]::add_CancelKeyPress($Script:CancelHandler)
}
Initialize-Cancellation

function Test-Cancellation {
    if ([SisouCancellation]::Requested) {
        $Script:CancellationRequested = $true
        $Script:CancellationReason = 'Ctrl+C'
    }
    return $Script:CancellationRequested
}

function Stop-ChildProcess {
    param([System.Diagnostics.Process] $Process)
    if (-not $Process) { return }
    try { $processId = $Process.Id } catch [System.InvalidOperationException] { return }
    if ($null -eq $processId -or $processId -le 0) { return }
    if ($Process -and -not $Process.HasExited) {
        try {
            & "$env:SystemRoot\System32\taskkill.exe" /PID $processId /T /F 2>&1 | Out-Null
        } catch { }
        if (-not $Process.HasExited) { $Process.Kill() }
        $null = $Process.WaitForExit(5000)
    }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string] $Value)
    '"' + ([regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1')) + '"'
}

###############################################################################
# LOGGING
###############################################################################
function Initialize-Logging {
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -Path $Script:LogDir -ItemType Directory -Force | Out-Null
    }
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $Script:LogFilePath = Join-Path $Script:LogDir "run-$ts.log"
    Write-Log "Log: $Script:LogFilePath"
}

function Write-Log {
    param(
        [string] $Message,
        [ValidateSet('DEBUG','INFO','WARNING','ERROR')]
        [string] $Level = "INFO"
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts][$Level] $Message"

    # DEBUG lines only reach the console when the caller asked for them.
    # They are always written to the log file.
    $toConsole = ($Level -ne "DEBUG") -or ($LogLevel -eq "DEBUG")
    if ($toConsole) {
        switch ($Level) {
            "ERROR"   { Write-Host $line -ForegroundColor Red     }
            "WARNING" { Write-Host $line -ForegroundColor Yellow  }
            "DEBUG"   { Write-Host $line -ForegroundColor DarkGray }
            default   { Write-Host $line -ForegroundColor Gray    }
        }
    }
    if ($Script:LogFilePath) {
        Add-Content -Path $Script:LogFilePath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Wait-CancellableSleep {
    param([int] $Seconds)

    $remaining = [Math]::Max(0, $Seconds * 10)
    while ($remaining -gt 0) {
        if (Test-Cancellation) { return $false }
        Start-Sleep -Milliseconds 100
        $remaining--
    }
    return (-not (Test-Cancellation))
}

###############################################################################
# STATE & REPORT  (privacy-safe - no absolute paths, no usernames)
###############################################################################
function Save-State {
    param([string] $Stage, [hashtable] $Data = @{})
    if (-not (Test-Path $Script:BaseDir)) {
        New-Item -Path $Script:BaseDir -ItemType Directory -Force | Out-Null
    }
    @{
        stage     = $Stage
        timestamp = (Get-Date).ToString('o')
        data      = $Data
    } | Write-JsonAtomic -Path $Script:StateFile
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Value,
        [Parameter(Mandatory)][string] $Path
    )
    process {
        $destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $temporary = $destination + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
        try {
            $json = $Value | ConvertTo-Json -Depth 10
            [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
            if ([IO.File]::Exists($destination)) {
                [IO.File]::Replace($temporary, $destination, [System.Management.Automation.Language.NullString]::Value)
            } else {
                [IO.File]::Move($temporary, $destination)
            }
        } finally {
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
    }
}

function Enter-RunnerLock {
    param([string] $Directory)
    # File sharing is enforced across processes and Windows sessions.
    return [IO.File]::Open((Join-Path $Directory 'runner.lock'),
        [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
}

function Save-Report {
    param([hashtable] $Report)
    $Report.completed = (Get-Date).ToString('o')
    try {
        $safeReport = $Report | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        foreach ($iso in $safeReport.isos) {
            if ($iso.PSObject.Properties['key']) { $iso.PSObject.Properties.Remove('key') }
            if ($iso.PSObject.Properties['validation'] -and $iso.validation -and -not $iso.validation.valid) {
                $iso.validation.reason = 'ISO header validation failed.'
            }
        }
        $safeReport.sisou.logfile = if ($Report.sisou.logfile) { [IO.Path]::GetFileName($Report.sisou.logfile) } else { $null }
        $safeReport.sisou.args = @()
        foreach ($field in @('stdout_tail','stderr_tail')) {
            if ($safeReport.sisou.PSObject.Properties[$field]) { $safeReport.sisou.PSObject.Properties.Remove($field) }
        }
        $safeReport.cancelReason = if ($Report.cancelled) { 'User cancellation' } else { $null }
        $safeReport | Write-JsonAtomic -Path $Script:ReportPath
        Write-Log "Report: $Script:ReportPath"
    } catch {
        Write-Log "Could not save report: $_" "WARNING"
    }
}

###############################################################################
# INSTALL ROOT  (ProgramData preferred; LocalAppData fallback if not writable)
###############################################################################
function Get-InstallRoot {
    try {
        if (-not (Test-Path $Script:BaseDir)) {
            New-Item -Path $Script:BaseDir -ItemType Directory -Force | Out-Null
        }
        $probe = Join-Path $Script:BaseDir '.__writetest'
        Set-Content -Path $probe -Value 'ok' -Encoding UTF8
        Remove-Item $probe -Force
        return $Script:BaseDir
    } catch {
        $alt = Join-Path $env:LOCALAPPDATA 'SISOU'
        if (-not (Test-Path $alt)) { New-Item -Path $alt -ItemType Directory -Force | Out-Null }
        return $alt
    }
}

###############################################################################
# PYTHON - VERSION PROBE
###############################################################################
function Get-PythonVersion {
    param([string] $Exe)
    $p = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $Exe
        $psi.Arguments              = '--version'
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        $p.Start() | Out-Null
        if (-not $p.WaitForExit(5000)) {
            Stop-ChildProcess $p
            return $null
        }
        $raw = ($p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()).Trim()
        if ($raw -match 'Python\s+(\d+\.\d+\.\d+)') {
            return [version] $Matches[1]
        }
    } catch { } finally {
        if ($p) { $p.Dispose() }
    }
    return $null
}

function Invoke-PythonCommand {
    param(
        [string]   $PythonExe,
        [string[]] $Arguments,
        [int]      $TimeoutMs = 60000
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $PythonExe
    $psi.Arguments              = ($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $psi.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $psi.EnvironmentVariables.Remove('PYTHONPATH')
    $psi.EnvironmentVariables.Remove('PYTHONHOME')

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try {
        $p.Start() | Out-Null
        $Script:ActiveProc = $p
        $stdoutTask = $p.StandardOutput.ReadToEndAsync()
        $stderrTask = $p.StandardError.ReadToEndAsync()
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not $p.WaitForExit(100)) {
            if ((Test-Cancellation) -or $timer.ElapsedMilliseconds -ge $TimeoutMs) {
                Stop-ChildProcess $p
                if (Test-Cancellation) { throw 'User cancellation' }
                return @{ ExitCode=-2; StdOut=''; StdErr="Timed out after $TimeoutMs ms." }
            }
        }
        return @{
            ExitCode = $p.ExitCode
            StdOut   = $stdoutTask.GetAwaiter().GetResult()
            StdErr   = $stderrTask.GetAwaiter().GetResult()
        }
    } catch {
        return @{ ExitCode=-1; StdOut=''; StdErr=$_.Exception.Message }
    } finally {
        $Script:ActiveProc = $null
        $p.Dispose()
    }
}

function Write-TextNoBom {
    param(
        [string] $Path,
        [string] $Value
    )

    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Repair-Utf8Bom {
    param([string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return $false }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
            Write-TextNoBom -Path $Path -Value $text
            Write-Log "Removed UTF-8 BOM from SISOU TOML: $Path" "WARNING"
            return $true
        }
    } catch {
        Write-Log "Could not inspect text encoding for '$Path': $_" "WARNING"
    }
    return $false
}

function ConvertTo-SisouPath {
    param([string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $trimmed = $Path.Trim()
    if ($trimmed -match '^[A-Za-z]:[\\/]?$') {
        return ($trimmed.Substring(0, 2) + '\')
    }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($trimmed)
}

function Add-DirectoryToPath {
    param([string] $Directory)

    if ([string]::IsNullOrWhiteSpace($Directory) -or -not (Test-Path $Directory)) { return }
    $parts = @($env:PATH -split ';' | Where-Object { $_ })
    $exists = @($parts | Where-Object { $_.TrimEnd('\') -ieq $Directory.TrimEnd('\') }).Count -gt 0
    if (-not $exists) {
        $env:PATH = $Directory + ';' + $env:PATH
    }
}

function Get-GpgExecutable {
    $cmd = Get-Command 'gpg.exe' -ErrorAction SilentlyContinue
    if ($cmd -and (Test-Path $cmd.Source)) { return $cmd.Source }

    $roots = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $roots += (Join-Path $root 'GnuPG\bin\gpg.exe')
        $roots += (Join-Path $root 'Gpg4win\bin\gpg.exe')
    }

    foreach ($path in $roots) {
        if (Test-Path $path) { return $path }
    }
    return $null
}

function Install-GpgViaWinget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log 'winget not available; cannot install GnuPG automatically.' "WARNING"
        return $false
    }

    foreach ($id in 'GnuPG.GnuPG','GnuPG.Gpg4win') {
        Write-Log "winget install --id $id"
        try {
            $p = Start-Process winget `
                   -ArgumentList @('install','--id',$id,'-e','--silent',
                                   '--accept-package-agreements','--accept-source-agreements') `
                   -Wait -PassThru -NoNewWindow
            if ($p.ExitCode -eq 0) {
                Write-Log "Installed GnuPG via winget: $id"
                return $true
            }
            if (Get-GpgExecutable) {
                Write-Log "GnuPG appears installed after winget response: $id"
                return $true
            }
            Write-Log "winget $id exit $($p.ExitCode)" "DEBUG"
        } catch {
            Write-Log "winget $id threw: $_" "DEBUG"
        }
    }
    return $false
}

function Resolve-GpgDependency {
    if ($SkipGpgCheck) {
        Write-Log 'Skipping GnuPG pre-flight (-SkipGpgCheck).' "WARNING"
        return $true
    }

    $gpg = Get-GpgExecutable
    if (-not $gpg -and $InstallGpg) {
        if (Install-GpgViaWinget) {
            $machinePath = [System.Environment]::GetEnvironmentVariable('PATH','Machine')
            $userPath = [System.Environment]::GetEnvironmentVariable('PATH','User')
            $env:PATH = $machinePath + ';' + $userPath + ';' + $env:PATH
            $gpg = Get-GpgExecutable
        }
    }

    if (-not $gpg -and -not $NonInteractive -and [Environment]::UserInteractive) {
        Write-Host ''
        Write-Host 'GnuPG is not installed or gpg.exe is not on PATH.' -ForegroundColor Yellow
        Write-Host 'SISOU can still download ISOs, but signature verification will be skipped for signed downloads.' -ForegroundColor Yellow
        Write-Host '[1/I] Install GnuPG with winget  [2/C] Continue without GnuPG  [3/E] Exit' -ForegroundColor Cyan
        $choice = (Read-Host 'Choice (default: 1)').Trim().ToUpper()
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -eq '1' -or $choice -eq 'I') {
            if (Install-GpgViaWinget) {
                $machinePath = [System.Environment]::GetEnvironmentVariable('PATH','Machine')
                $userPath = [System.Environment]::GetEnvironmentVariable('PATH','User')
                $env:PATH = $machinePath + ';' + $userPath + ';' + $env:PATH
                $gpg = Get-GpgExecutable
            }
        } elseif ($choice -eq '3' -or $choice -eq 'E') {
            Write-Log 'User exited before running without GnuPG.' "WARNING"
            exit 40
        } elseif ($choice -ne '2' -and $choice -ne 'C') {
            Write-Log "Unrecognised GnuPG choice '$choice'; continuing without GnuPG." "WARNING"
        }
    }

    if ($gpg) {
        $Script:GpgExe = $gpg
        Add-DirectoryToPath -Directory (Split-Path $gpg -Parent)
        Write-Log "GnuPG: $gpg"
        return $true
    }

    Write-Log 'GnuPG not found. SISOU may skip signature verification for signed ISOs.' "WARNING"
    return $false
}

###############################################################################
# PYTHON - SYSTEM PYTHON CANDIDATES (>=3.11, highest version first)
###############################################################################
function Get-SystemPythonCandidates {
    $candidates = New-Object 'System.Collections.Generic.List[string]'

    # PATH entries
    foreach ($name in 'python','python3') {
        Get-Command $name -ErrorAction SilentlyContinue -All |
            ForEach-Object { $candidates.Add($_.Source) }
    }
    # Per-user install root
    $localPy = Join-Path $env:LOCALAPPDATA 'Programs\Python'
    if (Test-Path $localPy) {
        Get-ChildItem -Path $localPy -Filter 'python.exe' -Recurse -Depth 2 `
                      -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add($_.FullName) }
    }
    # System-wide install roots
    foreach ($root in ($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        $dir = Join-Path $root 'Python'
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -Filter 'python.exe' -Recurse -Depth 2 `
                          -ErrorAction SilentlyContinue |
                ForEach-Object { $candidates.Add($_.FullName) }
        }
    }

    # Deduplicate (case-insensitive) and skip Windows Store app execution stubs
    $seen   = @{}
    $unique = $candidates | Where-Object {
        $k = $_.ToLower()
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $true } else { $false }
    } | Where-Object { $_ -notmatch '\\Microsoft\\WindowsApps\\' }

    $found = New-Object 'System.Collections.Generic.List[object]'
    foreach ($exe in $unique) {
        if (-not (Test-Path $exe -ErrorAction SilentlyContinue)) { continue }
        $ver = Get-PythonVersion -Exe $exe
        if (-not $ver) {
            Write-Log "  $(Split-Path $exe -Leaf) at $exe - version undetectable, skipping" "DEBUG"
            continue
        }
        Write-Log "  Python $ver : $exe" "DEBUG"
        if ($ver.Major -lt 3 -or ($ver.Major -eq 3 -and $ver.Minor -lt 12)) {
            Write-Log "  -> below 3.12, skipping" "DEBUG"; continue
        }
        $found.Add([PSCustomObject]@{ Path=$exe; Version=$ver }) | Out-Null
    }

    $sorted = @($found | Sort-Object Version -Descending)
    if ($sorted.Count -eq 0) { Write-Log 'No system Python >=3.12 found.' "DEBUG" }
    return $sorted
}

function Select-BestSystemPython {
    $candidates = @(Get-SystemPythonCandidates)
    if ($candidates.Count -eq 0) { return $null }
    Write-Log "Selected Python $($candidates[0].Version)"
    return $candidates[0].Path
}

###############################################################################
# PYTHON - MANAGED VENV RUNTIME
###############################################################################
function Get-ManagedRuntime {
    $root    = Get-InstallRoot
    $pyDir   = Join-Path $root 'runtime\python'
    $venvDir = Join-Path $root 'runtime\venv'
    $venvPy  = Join-Path $venvDir 'Scripts\python.exe'

    try {
        if (Test-Path $venvPy) {
            $existingVersion = Get-PythonVersion -Exe $venvPy
            if (-not $existingVersion -or $existingVersion -lt [version]'3.12') {
                throw 'Managed venv interpreter is missing or older than Python 3.12. Recreate the managed runtime.'
            }
            Write-Log 'Managed venv already present.'
            if (-not (Install-Sisou -PythonExe $venvPy)) { return $null }
            return $venvPy
        }

        if (-not (Test-Path (Split-Path $venvDir -Parent))) {
            New-Item -Path (Split-Path $venvDir -Parent) -ItemType Directory -Force | Out-Null
        }

        $candidates = @(Get-SystemPythonCandidates)
        if ($candidates.Count -gt 0) {
            $sourcePython = $candidates[0].Path
            Write-Log "Creating managed venv from Python $($candidates[0].Version)..."
            $venvCreate = Invoke-PythonCommand -PythonExe $sourcePython -Arguments @(
                '-m','venv',$venvDir
            ) -TimeoutMs 300000
            if ($venvCreate.ExitCode -ne 0) {
                throw "venv creation failed: $($venvCreate.StdErr)"
            }
        } else {
            if (-not (Test-Path (Split-Path $pyDir -Parent))) {
                New-Item -Path (Split-Path $pyDir -Parent) -ItemType Directory -Force | Out-Null
            }
            Write-Log 'No Python 3.12+ found for managed venv; downloading Python installer...'
            $url  = 'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe'
            $inst = Join-Path $env:TEMP ("py-inst-{0}.exe" -f [System.Guid]::NewGuid())
            Invoke-WebRequest -Uri $url -OutFile $inst -UseBasicParsing -ErrorAction Stop
            Write-Log 'Running silent Python installer...'
            $p = Start-Process -FilePath $inst `
                   -ArgumentList @('/quiet','InstallAllUsers=0','PrependPath=0',
                                   'Include_launcher=0','Include_test=0',"TargetDir=$pyDir") `
                   -Wait -PassThru -NoNewWindow
            Remove-Item $inst -Force -ErrorAction SilentlyContinue
            if ($p.ExitCode -ne 0) { throw "Installer exit code $($p.ExitCode)" }

            $pyExe = Join-Path $pyDir 'python.exe'
            if (-not (Test-Path $pyExe)) { throw "python.exe missing after install" }
            Write-Log 'Creating managed venv...'
            $venvCreate = Invoke-PythonCommand -PythonExe $pyExe -Arguments @(
                '-m','venv',$venvDir
            ) -TimeoutMs 300000
            if ($venvCreate.ExitCode -ne 0) {
                throw "venv creation failed: $($venvCreate.StdErr)"
            }
        }
        if (-not (Test-Path $venvPy)) { throw "venv python.exe missing after creation" }

        $pipUpgrade = Invoke-PythonCommand -PythonExe $venvPy -Arguments @(
            '-m','pip','install','--upgrade','pip','--quiet','--disable-pip-version-check'
        ) -TimeoutMs 300000
        if ($pipUpgrade.ExitCode -ne 0) { throw "pip upgrade failed: $($pipUpgrade.StdErr)" }

        $sisouInstall = Invoke-PythonCommand -PythonExe $venvPy -Arguments @(
            '-m','pip','install','--upgrade','sisou','--quiet',
            '--no-input','--disable-pip-version-check','--no-warn-script-location'
        ) -TimeoutMs 300000
        if ($sisouInstall.ExitCode -ne 0) { throw "pip install sisou failed: $($sisouInstall.StdErr)" }

        Write-Log 'Managed venv ready.'
        return $venvPy
    } catch {
        Write-Log "Managed venv bootstrap failed: $_" "ERROR"
        return $null
    }
}

###############################################################################
# PYTHON - WINGET FALLBACK
###############################################################################
function Install-PythonViaWinget {
    if (@(Get-SystemPythonCandidates).Count -gt 0) {
        Write-Log 'A supported Python is already installed; using it to create an isolated venv.'
        return $true
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log 'winget not available.' "WARNING"
        return $false
    }
    foreach ($id in 'Python.Python.3.12') {
        Write-Log "winget install --id $id"
        try {
            $p = Start-Process winget `
                   -ArgumentList @('install','--id',$id,'-e','--silent',
                                   '--accept-package-agreements','--accept-source-agreements') `
                   -Wait -PassThru -NoNewWindow
            if ($p.ExitCode -eq 0) { Write-Log "Installed via winget: $id"; return $true }
            Write-Log "winget $id exit $($p.ExitCode)" "DEBUG"
        } catch { Write-Log "winget $id threw: $_" "DEBUG" }
    }
    Write-Log 'winget could not install Python.' "WARNING"
    return $false
}

###############################################################################
# PYTHON - ENSURE SISOU IS INSTALLED
###############################################################################
function Install-Sisou {
    param([string] $PythonExe)
    if ($SkipPipUpgrade) {
        Write-Log 'Skipping pip upgrade (-SkipPipUpgrade).'
        return $true
    }
    Write-Log 'Ensuring sisou is up to date...'
    $res = Invoke-PythonCommand -PythonExe $PythonExe -Arguments @(
        '-m','pip','install','--upgrade','sisou','--quiet',
        '--no-input','--disable-pip-version-check','--no-warn-script-location'
    ) -TimeoutMs 300000
    $raw = @(($res.StdOut + [System.Environment]::NewLine + $res.StdErr) -split "(`r`n|`n|`r)")
    $raw | Where-Object { $_ -and $_ -notmatch '^\[notice\]' } |
           ForEach-Object { Write-Log $_ "DEBUG" }
    if ($res.ExitCode -eq 0) {
        return $true
    }

    $tail = @($raw | Where-Object { $_ } | Select-Object -Last 6) -join ' '
    Write-Log "pip install sisou failed: exit $($res.ExitCode). $tail" "ERROR"
    return $false
}

function Test-SisouRuntime {
    param([string] $PythonExe)

    $probe = 'import json,importlib.metadata; import sisou; import modules.updaters; print(json.dumps({"sisouVersion":importlib.metadata.version("sisou")}))'
    $res = Invoke-PythonCommand -PythonExe $PythonExe -Arguments @('-c', $probe) -TimeoutMs 60000
    if ($res.ExitCode -eq 0) {
        $dependencies = Invoke-PythonCommand -PythonExe $PythonExe -Arguments @('-m','pip','check') -TimeoutMs 60000
        if ($dependencies.ExitCode -ne 0) {
            $detail = ($dependencies.StdOut + $dependencies.StdErr).Trim()
            Write-Log "Managed runtime dependency check failed: $detail" 'WARNING'
            return @{ Success=$false; Message=$detail; Version=$null }
        }
        $metadata = ($res.StdOut.Trim() -split "`n" | Select-Object -Last 1) | ConvertFrom-Json
        Write-Log 'SISOU runtime import check passed.' "DEBUG"
        return @{ Success=$true; Message=''; Version=$metadata.sisouVersion }
    }

    $combined = ($res.StdOut + [System.Environment]::NewLine + $res.StdErr).Trim()
    $lines = @($combined -split "(`r`n|`n|`r)" | Where-Object { $_ })
    $tail = @($lines | Select-Object -Last 10) -join [System.Environment]::NewLine
    if ($combined -match 'libtorrent') {
        Write-Log 'SISOU runtime import check failed: libtorrent could not be loaded. This is usually a Python/SISOU dependency wheel compatibility issue.' "WARNING"
    } else {
        Write-Log 'SISOU runtime import check failed.' "WARNING"
        if ($lines.Count -gt 0) {
            Write-Log "Import failure detail: $($lines[-1])" "WARNING"
        }
    }
    Write-Log $tail "DEBUG"
    return @{ Success=$false; Message=$tail }
}

function Repair-SisouTorrentDependency {
    param([string] $PythonExe)

    Write-Log 'Attempting SISOU torrent dependency repair (libtorrent/torrentp)...' "WARNING"
    $res = Invoke-PythonCommand -PythonExe $PythonExe -Arguments @(
        '-m','pip','install','--upgrade','--force-reinstall','--no-cache-dir',
        'libtorrent','torrentp~=0.2.6',
        '--quiet','--no-input','--disable-pip-version-check','--no-warn-script-location'
    ) -TimeoutMs 300000

    $raw = @(($res.StdOut + [System.Environment]::NewLine + $res.StdErr) -split "(`r`n|`n|`r)")
    $raw | Where-Object { $_ -and $_ -notmatch '^\[notice\]' } |
           ForEach-Object { Write-Log $_ "DEBUG" }

    if ($res.ExitCode -ne 0) {
        $tail = @($raw | Where-Object { $_ } | Select-Object -Last 6) -join ' '
        Write-Log "Torrent dependency repair failed: exit $($res.ExitCode). $tail" "WARNING"
        return $false
    }
    return $true
}

function Get-PythonPureLib {
    param([string] $PythonExe)

    $res = Invoke-PythonCommand -PythonExe $PythonExe -Arguments @(
        '-c','import sysconfig; print(sysconfig.get_paths()["purelib"])'
    ) -TimeoutMs 30000
    if ($res.ExitCode -ne 0) { return $null }
    return ($res.StdOut -split "(`r`n|`n|`r)" | Where-Object { $_ } | Select-Object -First 1)
}

function Disable-SisouKaliTorrentUpdater {
    param(
        [string] $PythonExe,
        [string] $ConfigPath
    )

    $pureLib = Get-PythonPureLib -PythonExe $PythonExe
    if ([string]::IsNullOrWhiteSpace($pureLib)) {
        Write-Log 'Could not locate SISOU site-packages for Kali workaround.' "WARNING"
        return $false
    }

    $initPath = Join-Path $pureLib 'modules\updaters\__init__.py'
    if (-not (Test-Path $initPath)) {
        Write-Log 'Could not locate SISOU updater registry for Kali workaround.' "WARNING"
        return $false
    }

    try {
        $content = Get-Content -Path $initPath -Raw -ErrorAction Stop
        if ($content -notmatch 'KaliLinux import disabled by sisou-runner') {
            $patched = $content -replace 'from \.KaliLinux import KaliLinux', @'
# KaliLinux import disabled by sisou-runner when torrentp/libtorrent cannot load.
try:
    from .KaliLinux import KaliLinux
except ImportError:
    KaliLinux = None
'@
            Write-TextNoBom -Path $initPath -Value $patched
            Write-Log 'Patched managed SISOU venv to skip Kali updater when libtorrent cannot load.' "WARNING"
        }

        $defaultConfig = Join-Path $pureLib 'config\sisou.toml.default'
        if (Test-Path $defaultConfig) {
            Disable-SisouConfigUpdater -Path $defaultConfig -UpdaterName 'KaliLinux' | Out-Null
        }
        if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path $ConfigPath)) {
            Disable-SisouConfigUpdater -Path $ConfigPath -UpdaterName 'KaliLinux' | Out-Null
        }
        return $true
    } catch {
        Write-Log "Could not apply Kali updater workaround: $_" "WARNING"
        return $false
    }
}

function Disable-SisouConfigUpdater {
    param(
        [string] $Path,
        [string] $UpdaterName
    )

    try {
        Repair-Utf8Bom -Path $Path | Out-Null
        $text = Get-Content -Path $Path -Raw -ErrorAction Stop
        $pattern = "(?ms)(\[[^\]]*\.$([regex]::Escape($UpdaterName))\]\s*.*?enabled\s*=\s*)true"
        if ($text -match $pattern) {
            $updated = [regex]::Replace($text, $pattern, '${1}false', 1)
            Write-TextNoBom -Path $Path -Value $updated
            Write-Log "Disabled $UpdaterName in SISOU config: $Path" "WARNING"
            return $true
        }
    } catch {
        Write-Log "Could not update SISOU config '$Path': $_" "WARNING"
    }
    return $false
}

###############################################################################
# VENTOY DETECTION
#
# Ventoy creates two partitions on every USB drive:
#   Part 1 - large exFAT/NTFS data partition  (ISOs live here)
#   Part 2 - small FAT32 "VTOYEFI" partition  (32 MB, boot files)
#
# Windows mounts each as a separate drive letter. ventoy.json does NOT exist
# by default - it is an optional user-created plugin config.
#
# Detection order (most to least reliable):
#   1. VTOYEFI sibling - definitive: find the FAT32 "VTOYEFI" partition, then
#      return its sibling data partition on the same physical disk.
#   2. ventoy/ directory marker - present on the data partition at install time.
#   3. Volume label "Ventoy" - last resort for fresh/renamed drives.
###############################################################################
function Get-LogicalDisksWithDiskIndex {
    $result = @()
    try {
        $map = @{}
        Get-CimInstance Win32_DiskPartition -ErrorAction Stop | ForEach-Object {
            $part = $_
            Get-CimAssociatedInstance -InputObject $part `
                -ResultClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
            ForEach-Object { $map[$_.DeviceID] = $part.DiskIndex }
        }
        Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | ForEach-Object {
            $result += [PSCustomObject]@{
                DeviceID     = $_.DeviceID
                DriveType    = $_.DriveType
                VolumeName   = $_.VolumeName
                FileSystem   = $_.FileSystem
                ProviderName = $_.ProviderName
                DiskIndex    = if ($map.ContainsKey($_.DeviceID)) { $map[$_.DeviceID] } else { -1 }
            }
        }
    } catch { Write-Log "WMI disk query failed: $_" "WARNING" }
    return $result
}

function Get-VentoyCandidates {
    $all   = @(Get-LogicalDisksWithDiskIndex)
    $local = @($all | Where-Object { $_.DriveType -ne 4 -and [string]::IsNullOrEmpty($_.ProviderName) })

    $candidates = @()
    $efiDrives  = @()

    # Strategy 1 - VTOYEFI sibling (gold standard)
    $efiParts = @($local | Where-Object { $_.VolumeName -eq 'VTOYEFI' -and $_.FileSystem -eq 'FAT' })
    foreach ($efi in $efiParts) {
        $efiDrives += $efi.DeviceID
        if ($efi.DiskIndex -lt 0) { continue }
        $sibling = $local |
            Where-Object { $_.DiskIndex -eq $efi.DiskIndex -and $_.VolumeName -ne 'VTOYEFI' } |
            Select-Object -First 1
        if ($sibling -and ($candidates -notcontains $sibling.DeviceID)) {
            Write-Log "Strategy 1: Ventoy data partition $($sibling.DeviceID) (VTOYEFI sibling on disk $($efi.DiskIndex))" "DEBUG"
            $candidates += $sibling.DeviceID
        }
    }
    if ($candidates.Count -gt 0) { return $candidates }

    # Strategy 2 - ventoy/ directory (skip FAT and known EFI drives)
    foreach ($ld in $local) {
        if ($candidates -contains $ld.DeviceID) { continue }
        if ($efiDrives  -contains $ld.DeviceID) { continue }
        if ($ld.FileSystem -eq 'FAT')            { continue }
        $root = $ld.DeviceID + '\'
        if ((Test-Path (Join-Path $root 'ventoy')) -or
            (Test-Path (Join-Path $root 'ventoy\ventoy.json'))) {
            Write-Log "Strategy 2: Ventoy directory marker on $($ld.DeviceID)" "DEBUG"
            $candidates += $ld.DeviceID
        }
    }
    if ($candidates.Count -gt 0) { return $candidates }

    # Strategy 3 - default volume label fallback
    foreach ($ld in $local) {
        if ($candidates -contains $ld.DeviceID) { continue }
        if ($efiDrives  -contains $ld.DeviceID) { continue }
        if ($ld.DriveType -eq 2 -and $ld.FileSystem -eq 'exFAT' -and $ld.VolumeName -eq 'Ventoy') {
            Write-Log "Strategy 3: volume label match on $($ld.DeviceID)" "DEBUG"
            $candidates += $ld.DeviceID
        }
    }

    if ($candidates.Count -eq 0) {
        Write-Log 'No Ventoy data partition found. Attached local drives:' "DEBUG"
        $local | ForEach-Object {
            Write-Log "  $($_.DeviceID) type=$($_.DriveType) fs=$($_.FileSystem) label='$($_.VolumeName)' disk=$($_.DiskIndex)" "DEBUG"
        }
    }
    return $candidates
}

function Test-IsVentoy {
    param([string] $Root)
    $drive = $Root.Trim().TrimEnd('\').TrimEnd('/')
    if ($drive -match '^[A-Za-z]$') { $drive += ':' }
    return (@(Get-VentoyCandidates) -contains $drive)
}

function Select-VentoyDrive {
    # Explicit -Drive supplied
    if (-not [string]::IsNullOrWhiteSpace($Drive)) {
        if (Test-IsVentoy $Drive) { return $Drive }
        Write-Host "ERROR: '$Drive' is not a recognised Ventoy data partition." -ForegroundColor Red
        Write-Host "       Point to the large ISO partition (exFAT/NTFS, label 'Ventoy')," -ForegroundColor Yellow
        Write-Host "       not the small EFI partition (FAT32, label 'VTOYEFI')." -ForegroundColor Yellow
        Write-Host "       Omit -Drive to let auto-detection find it." -ForegroundColor Yellow
        exit 10
    }

    $candidates = @(Get-VentoyCandidates)

    if ($candidates.Count -eq 0) {
        Write-Host 'No Ventoy drives detected.' -ForegroundColor Yellow
        if ($NonInteractive) {
            Write-Host 'Non-interactive mode: exiting.' -ForegroundColor Red; exit 10
        }
        $retries = 0
        :outer while ($true) {
            Write-Host ''
            Write-Host 'Tips:' -ForegroundColor Yellow
            Write-Host '  1. Plug in your Ventoy USB drive and wait a moment.'
            Write-Host '  2. In a VM, verify USB passthrough is active.'
            if ($retries -ge 2) { Write-Host 'Still nothing after multiple retries.' -ForegroundColor Yellow }
            Write-Host '[R]etry  [M]anual path  [D]ry-run  [E]xit' -ForegroundColor Cyan
            $choice = (Read-Host 'Choice').Trim().ToUpper()
            switch ($choice) {
                'R' {
                    $retries++
                    $candidates = @(Get-VentoyCandidates)
                    if ($candidates.Count -gt 0) { break outer }
                    Write-Host 'Still no Ventoy drive found.' -ForegroundColor DarkYellow
                }
                'M' {
                    $m = (Read-Host 'Drive letter (e.g. E:)').Trim()
                    if (Test-IsVentoy $m) { return ($m.Substring(0,1).ToUpper() + ':') }
                    Write-Host "'$m' is not a valid Ventoy drive." -ForegroundColor Red
                }
                'D' {
                    Write-Host 'Switching to dry-run mode.' -ForegroundColor Yellow
                    $Script:DryRun = $true; return $null
                }
                'E' { Write-Host 'Exiting.' -ForegroundColor Red; exit 10 }
                default { Write-Host 'Enter R, M, D, or E.' -ForegroundColor Yellow }
            }
        }
    }

    if ($candidates.Count -eq 1) {
        Write-Log "Ventoy drive: $($candidates[0])"
        return $candidates[0]
    }

    if ($NonInteractive) {
        Write-Log "Non-interactive: using first Ventoy drive ($($candidates[0]))"
        return $candidates[0]
    }

    Write-Host ''; Write-Host 'Detected Ventoy drives:' -ForegroundColor Cyan
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        Write-Host "  [$i] $($candidates[$i])" -ForegroundColor Cyan
    }
    $raw = (Read-Host 'Select (Enter = 0)').Trim()
    $idx = 0
    if ($raw -and -not [int]::TryParse($raw, [ref]$idx)) {
        Write-Host 'Invalid input; using 0.' -ForegroundColor Yellow; $idx = 0
    }
    if ($idx -lt 0 -or $idx -ge $candidates.Count) {
        Write-Host "Out of range; using 0." -ForegroundColor Yellow; $idx = 0
    }
    return $candidates[$idx]
}

###############################################################################
# ISO DISCOVERY & HASHING
###############################################################################
function Get-IsoFiles {
    param([string] $Root)
    Write-Log "Scanning $Root for ISO files..."
    try {
        $scanParams = @{
            Path        = "$Root\"
            Filter      = '*.iso'
            File        = $true
            Force       = $true
            ErrorAction = 'SilentlyContinue'
        }
        if ($IsoScanDepth -ge 0) {
            $scanParams['Recurse'] = $true
            $scanParams['Depth'] = $IsoScanDepth
        } else {
            $scanParams['Recurse'] = $true
        }

        $items = @(Get-ChildItem @scanParams)
        if ($IncludeIsoPattern -and $IncludeIsoPattern.Count -gt 0) {
            $items = @($items | Where-Object {
                $name = $_.Name
                @($IncludeIsoPattern | Where-Object { $name -like $_ }).Count -gt 0
            })
        }
        if ($ExcludeIsoPattern -and $ExcludeIsoPattern.Count -gt 0) {
            $items = @($items | Where-Object {
                $name = $_.Name
                @($ExcludeIsoPattern | Where-Object { $name -like $_ }).Count -eq 0
            })
        }
        $items = @($items | Sort-Object FullName)
        Write-Log "Found $($items.Count) ISO file(s)."
        return $items
    } catch {
        throw "ISO scan failed: $_"
    }
}

function Get-FileHashes {
    param([object[]] $Files)
    if ($Files.Count -eq 0) { return @() }
    Write-Log "Computing SHA-256 for $($Files.Count) ISO(s)..."
    $results = @()
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $ht = $HashThrottle
        $results = $Files | ForEach-Object -Parallel {
            $f = $_
            try {
                $h = Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop
                [PSCustomObject]@{ FullName=$f.FullName; Name=$f.Name; Size=$f.Length; SHA256=$h.Hash; Error=$null }
            } catch {
                [PSCustomObject]@{ FullName=$f.FullName; Name=$f.Name; Size=$f.Length; SHA256=$null; Error=$_.Exception.Message }
            }
        } -ThrottleLimit $ht
    } else {
        foreach ($f in $Files) {
            if (Test-Cancellation) { throw 'Cancelled during hashing.' }
            try {
                $h = Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop
                $results += [PSCustomObject]@{ FullName=$f.FullName; Name=$f.Name; Size=$f.Length; SHA256=$h.Hash; Error=$null }
            } catch {
                $results += [PSCustomObject]@{ FullName=$f.FullName; Name=$f.Name; Size=$f.Length; SHA256=$null; Error=$_.Exception.Message }
            }
        }
    }
    return $results
}

function Test-IsoHeader {
    param([object] $File)

    $result = @{
        valid  = $false
        reason = ''
    }
    if ($File.Length -lt 34816) {
        $result.reason = 'File is too small to contain an ISO-9660 primary volume descriptor.'
        return $result
    }

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open,
                  [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $null = $stream.Seek(32769, [System.IO.SeekOrigin]::Begin)
        $buf = New-Object byte[] 5
        $read = $stream.Read($buf, 0, 5)
        $magic = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
        if ($magic -eq 'CD001') {
            $result.valid = $true
            $result.reason = 'ISO-9660 descriptor found.'
        } else {
            $result.reason = 'Missing ISO-9660 CD001 descriptor.'
        }
    } catch {
        $result.reason = "Could not read ISO header: $($_.Exception.Message)"
    } finally {
        if ($stream) { try { $stream.Dispose() } catch { } }
    }
    return $result
}

function New-IsoLookup {
    param([object[]] $Items)

    $lookup = @{}
    foreach ($item in $Items) {
        $name = $null
        if ($item -is [hashtable] -and $item.ContainsKey('key')) {
            $name = $item.key
        } elseif ($item.PSObject.Properties['FullName']) {
            $name = $item.FullName
        } elseif ($item -is [hashtable] -and $item.ContainsKey('name')) {
            $name = $item.name
        } elseif ($item.PSObject.Properties['Name']) {
            $name = $item.Name
        } elseif ($item.PSObject.Properties['name']) {
            $name = $item.name
        }
        if ($name -and -not $lookup.ContainsKey($name)) { $lookup[$name] = $item }
    }
    return $lookup
}

###############################################################################
# ISO BASE NAME  (heuristic for pairing removed/added as version updates)
###############################################################################
function Get-IsoBaseName {
    param([string] $FileName)
    $n = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    # Strip dotted version strings: 3.3.1.35  25.10.2  2026.02.01  22.3
    $n = $n -replace '\d+(\.[\d]+){1,}', ''
    # Strip remaining 4+-digit standalone numbers (build IDs, years)
    $n = $n -replace '\b\d{4,}\b', ''
    # Collapse multiple separators and trim ends
    $n = ($n -replace '[-_\.]+', '-').Trim('-')
    return $n.ToLower()
}

function ConvertFrom-EscapedUnicode {
    param([string] $Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    $map = @{
        '\u2588' = [string][char]0x2588
        '\u2589' = [string][char]0x2589
        '\u258a' = [string][char]0x258A
        '\u258b' = [string][char]0x258B
        '\u258c' = [string][char]0x258C
        '\u258d' = [string][char]0x258D
        '\u258e' = [string][char]0x258E
        '\u258f' = [string][char]0x258F
    }
    foreach ($key in $map.Keys) {
        $out = $out.Replace($key, $map[$key])
    }
    return $out
}

###############################################################################
# SISOU INVOCATION
# stdout  - async line reader (sisou log output is always \n-terminated)
# stderr  - async line reader (including tqdm carriage-return updates)
# Ctrl+C  - native flag polled by the run loop; child process tree is stopped
###############################################################################
function Invoke-Sisou {
    param(
        [string]   $PythonExe,
        [string]   $VentoyRoot,
        [int]      $TimeoutSec,
        [string[]] $ExtraArgs
    )

    $ts       = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $sisouLog = Join-Path $Script:LogDir "sisou-$ts.log"

    $hasF = @($ExtraArgs | Where-Object { $_ -eq '-f' -or $_ -eq '--log-file'    }).Count -gt 0
    $hasL = @($ExtraArgs | Where-Object { $_ -eq '-l' -or $_ -eq '--log-level'   }).Count -gt 0
    $targetPath = if (-not [string]::IsNullOrWhiteSpace($ConfigFile)) { $ConfigFile } else { $VentoyRoot }
    $targetPath = ConvertTo-SisouPath -Path $targetPath
    if (-not [string]::IsNullOrWhiteSpace($ConfigFile)) {
        Repair-Utf8Bom -Path $targetPath | Out-Null
    } else {
        $defaultToml = Join-Path $targetPath 'sisou.toml'
        Repair-Utf8Bom -Path $defaultToml | Out-Null
    }

    $argList = New-Object 'System.Collections.Generic.List[string]'
    $argList.Add('-m'); $argList.Add('sisou'); $argList.Add($targetPath)
    if ($LogLevel  -and -not $hasL) { $argList.Add('-l'); $argList.Add($LogLevel)  }
    if (-not $hasF)                 { $argList.Add('-f'); $argList.Add($sisouLog)   }
    foreach ($a in $ExtraArgs) { $argList.Add($a) }

    $quotedArgs = ($argList | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '

    Write-Log "Launching: sisou $targetPath"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $PythonExe
    $psi.Arguments              = $quotedArgs
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    
    # --- Fix 1: Onderdruk Python/Library warnings ---
    $psi.EnvironmentVariables['PYTHONUNBUFFERED']        = '1'
    $psi.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $psi.EnvironmentVariables['PYTHONWARNINGS']         = 'ignore' 
    $psi.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $psi.EnvironmentVariables.Remove('PYTHONPATH')
    $psi.EnvironmentVariables.Remove('PYTHONHOME')
    $psi.EnvironmentVariables['PATH'] = $env:PATH

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $stdOutQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    $stdErrQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    $stdOutBuf   = New-Object System.Text.StringBuilder
    $stdErrBuf   = New-Object System.Text.StringBuilder

    $outHandler = { if ($EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) } }
    $errHandler = { if ($EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) } }

    $jobOut = $null; $jobErr = $null
    $logStream = $null; $logReader = $null

    try {
        $proc.Start() | Out-Null
        $Script:ActiveProc = $proc

        $jobOut = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $outHandler -MessageData $stdOutQueue
        $jobErr = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived  -Action $errHandler -MessageData $stdErrQueue

        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $lastFileName    = $null
        $lastLogWasError = $false
        
        # Console breedte voor schone 'overwrites'
        $conW = 80
        try { $conW = [System.Console]::WindowWidth } catch { }
        if ($conW -le 0) { $conW = 80 }

        while (-not $proc.HasExited) {
            if (Test-Cancellation) {
                Write-Log 'Cancellation requested - stopping sisou child process.' "WARNING"
                Stop-ChildProcess $proc
                $proc.WaitForExit(5000) | Out-Null
                return @{ ExitCode=-3; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString(); LogFile=$sisouLog; Cancelled=$true }
            }

            $line = $null
            
            # --- STDOUT (Normale Logs) ---
            while ($stdOutQueue.TryDequeue([ref]$line)) {
                [void]$stdOutBuf.AppendLine($line)
                $displayLine = ConvertFrom-EscapedUnicode -Text $line
                # Als er nog een voortgangsbalk stond, zet die op een nieuwe regel
                if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }
                Write-Host $displayLine
            }

            # --- STDERR (Progress Bars & Filtering) ---
            while ($stdErrQueue.TryDequeue([ref]$line)) {
                # Fix 2: Extra filter voor hardnekkige UserWarnings
                if ($line -match 'UserWarning:' -or $line -match 'warnings\.warn') { continue }

                [void]$stdErrBuf.AppendLine($line)
                $displayLine = ConvertFrom-EscapedUnicode -Text $line
                
                # Detecteer tqdm progress bar (bv. "ubuntu.iso: 50%|###")
                if ($displayLine -match '^(.+?):\s+\d+%.*\|') {
                    $currentFile = $Matches[1]

                    # Fix 3: Als we wisselen van ISO, sluit de vorige netjes af met een Enter
                    if ($null -ne $lastFileName -and $currentFile -ne $lastFileName) {
                        Write-Host "" 
                    }
                    $lastFileName = $currentFile

                    $disp = if ($displayLine.Length -ge $conW) { $displayLine.Substring(0, $conW - 1) } else { $displayLine.PadRight($conW - 1) }
                    Write-Host -NoNewline "`r$disp" -ForegroundColor DarkGray
                } 
                elseif ($displayLine -match '100%\|') {
                    # Voltooid: schrijf de 100% regel definitief weg
                    Write-Host "`r$($displayLine.PadRight($conW - 1))" -ForegroundColor DarkGray
                    $lastFileName = $null
                }
                else {
                    # Andere stderr (echte errors)
                    if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }
                    Write-Host $displayLine -ForegroundColor Red
                }
            }

            # --- SISOU LOG FILE (per-ISO status lines not emitted to stdout/stderr) ---
            if (-not $logReader -and (Test-Path $sisouLog -ErrorAction SilentlyContinue)) {
                try {
                    $logStream = [System.IO.File]::Open($sisouLog, [System.IO.FileMode]::Open,
                                 [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $logReader = New-Object System.IO.StreamReader($logStream, [System.Text.Encoding]::UTF8)
                } catch { }
            }
            if ($logReader) {
                $logLine = $null
                while ($null -ne ($logLine = $logReader.ReadLine())) {
                    if ($logLine -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+ - (INFO|WARNING|ERROR) - (.+)$') {
                        $lvl = $Matches[1]; $msg = ConvertFrom-EscapedUnicode -Text $Matches[2]
                        if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                        $lc = switch ($lvl) { 'WARNING' { 'Yellow' } 'ERROR' { 'DarkRed' } default { 'DarkCyan' } }
                        Write-Host "[sisou][$lvl] $msg" -ForegroundColor $lc
                        $lastLogWasError = ($lvl -eq 'ERROR')
                    } elseif ($lastLogWasError -and $logLine.Trim() -ne '') {
                        if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                        Write-Host "         $(ConvertFrom-EscapedUnicode -Text $logLine)" -ForegroundColor DarkRed
                    } elseif ($logLine.Trim() -eq '') {
                        $lastLogWasError = $false
                    }
                }
            }

            Start-Sleep -Milliseconds 50
            
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
                Write-Log "Timeout (${TimeoutSec}s) - killing sisou." "WARNING"
                Stop-ChildProcess $proc
                $proc.WaitForExit(5000) | Out-Null
                return @{ ExitCode=-2; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString(); LogFile=$sisouLog; Cancelled=$false }
            }
        }

        $proc.WaitForExit()

        # Laatste buffers legen
        while ($stdOutQueue.TryDequeue([ref]$line)) { 
            [void]$stdOutBuf.AppendLine($line)
            if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }; Write-Host (ConvertFrom-EscapedUnicode -Text $line)
        }
        while ($stdErrQueue.TryDequeue([ref]$line)) {
            [void]$stdErrBuf.AppendLine($line)
            if ($line -match 'UserWarning:' -or $line -match 'warnings\.warn') { continue }
            if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }
            Write-Host (ConvertFrom-EscapedUnicode -Text $line) -ForegroundColor DarkGray
        }
        if ($logReader) {
            $logLine = $null
            while ($null -ne ($logLine = $logReader.ReadLine())) {
                if ($logLine -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+ - (INFO|WARNING|ERROR) - (.+)$') {
                    $lvl = $Matches[1]; $msg = ConvertFrom-EscapedUnicode -Text $Matches[2]
                    if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                    $lc = switch ($lvl) { 'WARNING' { 'Yellow' } 'ERROR' { 'DarkRed' } default { 'DarkCyan' } }
                    Write-Host "[sisou][$lvl] $msg" -ForegroundColor $lc
                    $lastLogWasError = ($lvl -eq 'ERROR')
                } elseif ($lastLogWasError -and $logLine.Trim() -ne '') {
                    if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                    Write-Host "         $(ConvertFrom-EscapedUnicode -Text $logLine)" -ForegroundColor DarkRed
                } elseif ($logLine.Trim() -eq '') {
                    $lastLogWasError = $false
                }
            }
        }

        Write-Host "" # Eindig altijd met een schone regel

        if (Test-Cancellation) {
            return @{ ExitCode=-3; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString(); LogFile=$sisouLog; Cancelled=$true }
        }

        return @{ ExitCode=$proc.ExitCode; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString(); LogFile=$sisouLog; Cancelled=$false }

    } catch {
        return @{ ExitCode=-1; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString() + $_; LogFile=$sisouLog; Cancelled=[bool]$Script:CancellationRequested }
    } finally {
        Stop-ChildProcess $proc
        if ($jobOut) { Unregister-Event -SourceIdentifier $jobOut.Name; Remove-Job $jobOut -Force }
        if ($jobErr) { Unregister-Event -SourceIdentifier $jobErr.Name; Remove-Job $jobErr -Force }
        if ($logReader) { try { $logReader.Dispose() } catch { } }
        if ($logStream) { try { $logStream.Dispose() } catch { } }
        $Script:ActiveProc = $null
        $proc.Dispose()
    }
}

###############################################################################
# PRE-FLIGHT VALIDATION
###############################################################################
function Assert-Inputs {
    if ($LogLevel -and @('DEBUG','INFO','WARNING','ERROR','CRITICAL') -notcontains $LogLevel) {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: -LogLevel must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.' -ForegroundColor Red
        Write-Host "  You supplied: $LogLevel" -ForegroundColor Yellow
        exit 40
    }
    if (-not [string]::IsNullOrWhiteSpace($Drive)) {
        # Normalise: accept "E", "E:", "E:\"
        $driveLetter = $Drive.TrimEnd('\').TrimEnd('/').TrimEnd(':')
        if ($driveLetter -notmatch '^[A-Za-z]$') {
            Write-Host '' -ForegroundColor Red
            Write-Host 'ERROR: Invalid drive letter.' -ForegroundColor Red
            Write-Host "  You supplied : '$Drive'" -ForegroundColor Yellow
            Write-Host '  Expected     : a single letter, e.g. E or E: or E:\' -ForegroundColor Yellow
            Write-Host '  Tip          : omit -Drive to let auto-detection find your Ventoy drive.' -ForegroundColor Cyan
            exit 10
        }
        $script:Drive = "${driveLetter}:"
        $root = "${driveLetter}:\"
        if (-not (Test-Path $root)) {
            Write-Host '' -ForegroundColor Red
            Write-Host "ERROR: Drive '${driveLetter}:' is not accessible." -ForegroundColor Red
            Write-Host '  Make sure the drive is plugged in and Windows has assigned it a letter.' -ForegroundColor Yellow
            Write-Host '  Tip: open Disk Management (diskmgmt.msc) to verify the drive letter.' -ForegroundColor Cyan
            exit 10
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ConfigFile) -and -not (Test-Path $ConfigFile)) {
        Write-Host '' -ForegroundColor Red
        Write-Host "ERROR: Config file not found." -ForegroundColor Red
        Write-Host "  Path supplied: '$ConfigFile'" -ForegroundColor Yellow
        Write-Host '  Make sure the path is correct and the file exists.' -ForegroundColor Yellow
        exit 40
    }
    if (-not [string]::IsNullOrWhiteSpace($LogDir)) {
        if (-not (Test-Path $LogDir)) {
            try { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
            catch {
                Write-Host '' -ForegroundColor Red
                Write-Host 'ERROR: Cannot create log directory.' -ForegroundColor Red
                Write-Host "  Path   : '$LogDir'" -ForegroundColor Yellow
                Write-Host "  Reason : $_" -ForegroundColor Yellow
                Write-Host '  Tip    : check permissions, or omit -LogDir to use the default.' -ForegroundColor Cyan
                exit 40
            }
        }
    }
    if ($RetryCount -lt 1) {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: -RetryCount must be at least 1.' -ForegroundColor Red
        Write-Host "  You supplied: $RetryCount" -ForegroundColor Yellow
        exit 40
    }
    if ($TimeoutSeconds -lt 30) {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: -TimeoutSeconds must be at least 30.' -ForegroundColor Red
        Write-Host "  You supplied: $TimeoutSeconds" -ForegroundColor Yellow
        exit 40
    }
    if ($HashThrottle -lt 1) {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: -HashThrottle must be at least 1.' -ForegroundColor Red
        Write-Host "  You supplied: $HashThrottle" -ForegroundColor Yellow
        exit 40
    }
    if ($IsoScanDepth -lt -1) {
        Write-Host '' -ForegroundColor Red
        Write-Host 'ERROR: -IsoScanDepth must be -1 or greater.' -ForegroundColor Red
        Write-Host "  You supplied: $IsoScanDepth" -ForegroundColor Yellow
        exit 40
    }
}

###############################################################################
# RUNTIME RESOLUTION
###############################################################################
function Resolve-SisouPython {
    $selectedPath = $null
    $selectedType = ''

    if (-not $UseWinget) {
        Write-Log 'Trying managed SISOU venv...'
        $selectedType = 'managed'
        $selectedPath = Get-ManagedRuntime
        if ($selectedPath) {
            $health = Test-SisouRuntime -PythonExe $selectedPath
            if (-not $health.Success -and $health.Message -match 'libtorrent') {
                if (Repair-SisouTorrentDependency -PythonExe $selectedPath) {
                    $health = Test-SisouRuntime -PythonExe $selectedPath
                }
                if (-not $health.Success) {
                    $configForWorkaround = if (-not [string]::IsNullOrWhiteSpace($ConfigFile)) {
                        $ConfigFile
                    } elseif (-not [string]::IsNullOrWhiteSpace($Script:SelectedVentoyRoot)) {
                        Join-Path (ConvertTo-SisouPath -Path $Script:SelectedVentoyRoot) 'sisou.toml'
                    } else {
                        $null
                    }
                    if (Disable-SisouKaliTorrentUpdater -PythonExe $selectedPath -ConfigPath $configForWorkaround) {
                        $health = Test-SisouRuntime -PythonExe $selectedPath
                    }
                }
            }
            if (-not $health.Success) {
                Write-Log 'Managed SISOU venv cannot import SISOU successfully.' "WARNING"
                $selectedPath = $null
            }
        }
    }

    if (-not $selectedPath) {
        if (-not $UseWinget -and @(Get-SystemPythonCandidates).Count -gt 0) {
            Write-Log 'Managed SISOU environment failed; shared Python packages will not be modified.' "ERROR"
            return $null
        }
        if (-not (Install-PythonViaWinget)) { return $null }
        $env:PATH = [Environment]::GetEnvironmentVariable('PATH','Machine') + ';' +
                    [Environment]::GetEnvironmentVariable('PATH','User')
        $selectedPath = Get-ManagedRuntime
        $selectedType = 'managed'
        if (-not $selectedPath) { return $null }
        $health = Test-SisouRuntime -PythonExe $selectedPath
        if (-not $health.Success) { return $null }
    }

    $selectedVersion = Get-PythonVersion -Exe $selectedPath
    return [PSCustomObject]@{
        Path    = $selectedPath
        Type    = $selectedType
        SisouVersion = $health.Version
        Version = if ($selectedVersion) { $selectedVersion.ToString() } else { 'unknown' }
    }
}

###############################################################################
# INTERACTIVE LAUNCH MENU
# Shown when the script is invoked with no arguments, e.g. via right-click
# "Run with PowerShell" or a plain desktop shortcut.
###############################################################################
function Get-MenuParameters {
    param([System.Collections.IDictionary] $BoundParameters)
    $parameters = @{}
    foreach ($key in $BoundParameters.Keys) { $parameters[$key] = $BoundParameters[$key] }
    $parameters['Menu'] = $true
    $parameters['Drive'] = $Drive
    $parameters['ConfigFile'] = $ConfigFile
    if ($LogLevel) { $parameters['LogLevel'] = $LogLevel }
    return $parameters
}

function Show-LastReport {
    $paths = @((Join-Path $Script:BaseDir 'report.json'),
        (Join-Path (Join-Path $env:LOCALAPPDATA 'SISOU') 'report.json')) | Select-Object -Unique
    $files = @($paths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        ForEach-Object { Get-Item -LiteralPath $_ } | Sort-Object LastWriteTimeUtc -Descending)
    if ($files.Count -eq 0) { Write-Host 'No saved report found.' -ForegroundColor Yellow; return }
    try {
        $saved = Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json
        if (-not $saved.PSObject.Properties['isos'] -or -not $saved.PSObject.Properties['mode']) {
            throw 'Missing report fields.'
        }
        Write-Host "Last report: $($files[0].FullName)" -ForegroundColor Cyan
        Write-Host "Mode: $($saved.mode)"
        if ($saved.PSObject.Properties['completed']) { Write-Host "Completed: $($saved.completed)" }
        if ($saved.PSObject.Properties['runnerVersion']) { Write-Host "Runner: $($saved.runnerVersion)" }
        foreach ($status in @('updated','added','removed','unchanged','pending','hash-error')) {
            $count = @($saved.isos | Where-Object { $_.status -eq $status }).Count
            Write-Host "  ${status}: $count"
        }
        if ($saved.PSObject.Properties['cancelled'] -and $saved.cancelled) {
            Write-Host 'Run was cancelled.' -ForegroundColor Yellow
        }
        if ($saved.PSObject.Properties['sisou'] -and $saved.sisou) {
            if ($saved.sisou.PSObject.Properties['exitcode']) { Write-Host "SISOU exit: $($saved.sisou.exitcode)" }
            if ($saved.sisou.PSObject.Properties['updaterErrors']) { Write-Host "Updater errors: $($saved.sisou.updaterErrors)" }
        }
    } catch {
        Write-Host "Could not read saved report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Show-LaunchMenu {
    $showBanner = $true
    while ($true) {
        if ($showBanner) {
            Clear-Host
            $w = 52
            Write-Host ('=' * $w) -ForegroundColor Cyan
            Write-Host "  sisou-runner v$ScriptVersion  --  ISO Update Tool" -ForegroundColor Cyan
            Write-Host ('=' * $w) -ForegroundColor Cyan
            Write-Host ''
            Write-Host '  What would you like to do?' -ForegroundColor White
            Write-Host "  Drive: $(if ($Drive) { $Drive } else { 'Auto-detect' })" -ForegroundColor DarkGray
            Write-Host "  Config: $(if ($ConfigFile) { $ConfigFile } else { 'sisou.toml on selected drive' })" -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '  [1]  Run            Auto-detect Ventoy drive and update ISOs' -ForegroundColor Green
            Write-Host '  [2]  Dry run        Preview what would be updated (no changes)' -ForegroundColor Cyan
            Write-Host '  [3]  Debug run      Same as Run, with verbose DEBUG logging' -ForegroundColor Yellow
            Write-Host '  [4]  Help           Show all parameters and exit codes' -ForegroundColor Gray
            Write-Host '  [5]  Drive          Select a drive letter or use auto-detect' -ForegroundColor Gray
            Write-Host '  [6]  Config         Select a SISOU TOML file or use drive default' -ForegroundColor Gray
            Write-Host '  [7]  Last report    Show the most recent saved run' -ForegroundColor Gray
            Write-Host '  [Q]  Quit'
            Write-Host ''
            Write-Host '  Tip: pass arguments to skip this menu, e.g.  .\sisou-runner.ps1 -DryRun' -ForegroundColor DarkGray
            Write-Host ''
            $showBanner = $false
        }
        if (Test-Cancellation) { return @{ Action='cancel' } }
        $answer = Read-Host '  Choice (default: 2, preview)'
        if (Test-Cancellation) { return @{ Action='cancel' } }
        if ($null -eq $answer) { return @{ Action='quit' } }
        $c = $answer.Trim().ToUpper()
        switch ($c) {
            ''  { return @{ Action='run'; DryRun=$true; LogLevel=$null   } }
            '1' { return @{ Action='run'; DryRun=$false; LogLevel=$null   } }
            '2' { return @{ Action='run'; DryRun=$true;  LogLevel=$null   } }
            '3' { return @{ Action='run'; DryRun=$false; LogLevel='DEBUG' } }
            '4' {
                Clear-Host
                Write-HelpText
                Write-Host ''
                Write-Host '  Press Enter to return to the menu...' -ForegroundColor DarkGray
                $null = Read-Host
                $showBanner = $true   # redraw menu after returning
            }
            '5' {
                $selected = ([string](Read-Host 'Drive (e.g. F:, Enter = auto-detect)')).Trim()
                if (-not $selected) { $script:Drive = $null }
                elseif ($selected -match '^([A-Za-z])(?::[\\/]*)?$') {
                    $script:Drive = $Matches[1].ToUpper() + ':'
                } else { Write-Host 'Enter a drive letter such as F:.' -ForegroundColor Yellow }
                $showBanner = $true
            }
            '6' {
                $selected = ([string](Read-Host 'TOML path (Enter = drive default)')).Trim().Trim('"')
                if (-not $selected) { $script:ConfigFile = $null }
                elseif (Test-Path -LiteralPath $selected -PathType Leaf) {
                    $script:ConfigFile = ConvertTo-SisouPath $selected
                } else { Write-Host 'Config file was not found; selection kept.' -ForegroundColor Yellow }
                $showBanner = $true
            }
            '7' {
                Show-LastReport
                $null = Read-Host 'Press Enter to return to the menu'
                $showBanner = $true
            }
            'Q' { return @{ Action='quit' } }
            default { Write-Host '  Please enter 1-7 or Q.' -ForegroundColor Yellow }
        }
    }
}

###############################################################################
# ENTRY POINT
###############################################################################
# Report intentionally omits full paths (GDPR / privacy).
# ISO entries use filename only; drive letter is stored as a single character.
$Report = @{
    runnerVersion = $ScriptVersion
    started  = (Get-Date).ToString('o')
    drive    = $null          # drive letter only, e.g. "F"
    mode     = if ($Script:DryRun) { 'dry-run' } else { 'live' }
    runtime  = @{ type=''; pythonVersion=''; sisouVersion='' }
    dependencies = @{ gpg = @{ found=$false; exe=$null } }
    config   = @{
        advancedConfig = if ([string]::IsNullOrWhiteSpace($AdvancedConfigFile)) { $null } else { [System.IO.Path]::GetFileName($AdvancedConfigFile) }
        isoScanDepth = $IsoScanDepth
        includeIsoPattern = $IncludeIsoPattern
        excludeIsoPattern = $ExcludeIsoPattern
        validateIsoHeaders = [bool]$ValidateIsoHeaders
    }
    isos     = @()
    sisou    = @{ exitcode=$null; logfile=$null; attempts=0; args=$SisouArgs }
    cancelled = $false
    cancelReason = $null
    completed = $null
}

try {
    # -- Interactive launch menu (no-argument invocation) ------------------
    if ($Menu -and $NonInteractive) {
        Write-Host 'ERROR: -Menu cannot be combined with -NonInteractive.' -ForegroundColor Red
        exit 40
    }
    if (($PSBoundParameters.Count -eq 0 -or $Menu) -and -not $NonInteractive -and [Environment]::UserInteractive) {
        $menuSelection = Show-LaunchMenu
        switch ($menuSelection.Action) {
            'quit' {
                $Script:PauseAtExit = $false   # user already interacted; no double-prompt
                exit 0
            }
            'cancel' { $Script:PauseAtExit = $false; exit 130 }
            'run' {
                $Script:PauseAtExit = $true    # menu -> always a direct-launch window
                $Script:FromMenu = $true
                $Script:DryRun = [bool]$menuSelection.DryRun
                if ($menuSelection.LogLevel) { $LogLevel = $menuSelection.LogLevel }
            }
        }
    }

    $Script:BaseDir = Get-InstallRoot
    try { $Script:RunLock = Enter-RunnerLock -Directory $Script:BaseDir }
    catch [System.IO.IOException] {
        Write-Host 'Another SISOU runner is using this runtime. Close it before starting another run.' -ForegroundColor Yellow
        exit 60
    }
    $Script:ReportPath = Join-Path $Script:BaseDir 'report.json'
    $Script:StateFile = Join-Path $Script:BaseDir 'state.json'
    if ([string]::IsNullOrWhiteSpace($LogDir)) { $Script:LogDir = Join-Path $Script:BaseDir 'logs' }
    Initialize-Logging
    Write-Log "sisou-runner.ps1 v$ScriptVersion starting (PowerShell $($PSVersionTable.PSVersion))"

    Assert-Inputs
    if (Test-Cancellation) { throw 'Cancelled before drive selection.' }

    # -- Ventoy selection --------------------------------------------------
    $ventoy       = Select-VentoyDrive
    $ventoy       = ConvertTo-SisouPath -Path $ventoy
    $Script:SelectedVentoyRoot = $ventoy
    $Report.drive = if ($ventoy) { $ventoy[0] } else { $null }  # store drive letter only
    $Report.mode  = if ($Script:DryRun) { 'dry-run' } else { 'live' }
    Save-State 'drive-selected' @{ drive = $Report.drive }

    # -- Dry-run short-circuit ----------------------------------------------
    if ($Script:DryRun) {
        if ($ventoy) {
            $files = @(Get-IsoFiles -Root $ventoy)
            Write-Host ''
            Write-Host '--- DRY-RUN: no changes will be made ---' -ForegroundColor Cyan
            Write-Host "Drive  : $ventoy" -ForegroundColor Cyan
            Write-Host 'Python : not checked in dry-run mode' -ForegroundColor Cyan
            Write-Host "ISOs   : $($files.Count) file(s) found" -ForegroundColor Cyan
            if ($IsoScanDepth -ge 0 -or $IncludeIsoPattern -or $ExcludeIsoPattern) {
                Write-Host "Scan   : depth=$IsoScanDepth include='$($IncludeIsoPattern -join ',')' exclude='$($ExcludeIsoPattern -join ',')'" -ForegroundColor Cyan
            }
            if ($files.Count -gt 0) {
                Write-Host ''
                Write-Host 'ISO files on drive:' -ForegroundColor DarkCyan
                foreach ($f in ($files | Sort-Object Name)) {
                    $sizeMB = [Math]::Round($f.Length / 1MB, 1)
                    Write-Host ("  {0,-60} {1,8} MB" -f $f.Name, $sizeMB) -ForegroundColor Gray
                }
            }
            Write-Host ''
            Write-Host 'Actions that would be taken:' -ForegroundColor DarkCyan
            Write-Host "  1. Check GnuPG availability for SISOU signature verification" -ForegroundColor Gray
            Write-Host "  2. Select a healthy Python runtime and ensure sisou imports cleanly" -ForegroundColor Gray
            Write-Host "  3. pip install --upgrade sisou$(if ($SkipPipUpgrade) { ' (skipped by -SkipPipUpgrade)' } else { '' })" -ForegroundColor Gray
            $sisouTarget = if ($ConfigFile) { ConvertTo-SisouPath -Path $ConfigFile } else { ConvertTo-SisouPath -Path $ventoy }
            Write-Host "  4. python -m sisou $sisouTarget$(if ($LogLevel) { " -l $LogLevel" } else { '' })" -ForegroundColor Gray
            $actionNumber = 5
            if ($RetryCount -gt 1) {
                Write-Host "  $actionNumber. Retry up to $($RetryCount - 1) time(s) on failure (backoff: 2s, 4s, ...)" -ForegroundColor Gray
                $actionNumber++
            }
            if ($ValidateIsoHeaders) {
                Write-Host "  $actionNumber. Validate ISO-9660 CD001 headers before live runs" -ForegroundColor Gray
                $actionNumber++
            }
            Write-Host "  $actionNumber. Write report to $Script:ReportPath" -ForegroundColor Gray
            Write-Host ''
            Write-Log "[DryRun] $($files.Count) ISO(s) on $ventoy - sisou would run here."
        } else {
            Write-Host '' 
            Write-Host '--- DRY-RUN: no Ventoy drive detected ---' -ForegroundColor Yellow
            Write-Log '[DryRun] No Ventoy drive; nothing to do.'
        }
        Save-Report -Report $Report
        exit 0
    }

    # -- GnuPG pre-flight --------------------------------------------------
    $gpgAvailable = Resolve-GpgDependency
    $Report.dependencies.gpg.found = [bool]$gpgAvailable
    $Report.dependencies.gpg.exe = if ($Script:GpgExe) { [System.IO.Path]::GetFileName($Script:GpgExe) } else { $null }
    if (Test-Cancellation) { throw 'Cancelled before runtime selection.' }

    # -- Runtime selection -------------------------------------------------
    $runtime = Resolve-SisouPython
    if (Test-Cancellation) { throw 'Cancelled during runtime setup.' }
    if (-not $runtime) { exit 20 }
    $py = $runtime.Path
    $Report.runtime.type = $runtime.Type
    $Report.runtime.pythonVersion = $runtime.Version
    $Report.runtime.sisouVersion = $runtime.SisouVersion
    Write-Log "Python $($Report.runtime.pythonVersion) ($($Report.runtime.type))"
    if (Test-Cancellation) { throw 'Cancelled before ISO scan.' }

    # Reject malformed TOML once, before attempts or downloads.
    $configToCheck = if ($ConfigFile) { ConvertTo-SisouPath $ConfigFile } else { Join-Path $ventoy 'sisou.toml' }
    if (Test-Path -LiteralPath $configToCheck -PathType Leaf) {
        Repair-Utf8Bom -Path $configToCheck | Out-Null
        $configCheck = Invoke-PythonCommand -PythonExe $py -Arguments @('-c',
            'import sys,tomllib; from pathlib import Path; tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))', $configToCheck)
        if (Test-Cancellation) { throw 'Cancelled during config validation.' }
        if ($configCheck.ExitCode -ne 0) {
            Write-Log "SISOU TOML validation failed: $($configCheck.StdErr)" 'ERROR'
            Save-State 'validation-failed' @{ reason='Invalid SISOU TOML' }
            Save-Report $Report
            exit 40
        }
    }

    # -- Validate drive + ISOs ---------------------------------------------
    if (-not $ventoy) { Write-Log 'No Ventoy drive.' "ERROR"; exit 10 }

    $isoFiles = @(Get-IsoFiles -Root $ventoy)
    if ($isoFiles.Count -eq 0) { Write-Log 'No existing ISOs; SISOU may populate the drive from its config.' }

    # -- Pre-run snapshot (mtime + size; optional header/SHA validation) -----
    $isoReport = New-Object 'System.Collections.Generic.List[hashtable]'
    $invalidIsoCount = 0
    foreach ($f in $isoFiles) {
        $header = if ($ValidateIsoHeaders) { Test-IsoHeader -File $f } else { $null }
        if ($header -and -not $header.valid) { $invalidIsoCount++ }
        $isoReport.Add(@{
            name            = $f.Name          # filename only - no full path
            key             = $f.FullName
            size            = $f.Length
            last_write_utc  = $f.LastWriteTimeUtc.ToString('o')
            pre_sha256      = $null
            post_sha256     = $null
            validation      = if ($header) { $header } else { $null }
            status          = 'pending'
        })
    }
    if ($invalidIsoCount -gt 0) {
        $Report.isos = $isoReport.ToArray()
        Save-State 'validation-failed' @{ isoCount=$isoReport.Count; invalidIsoCount=$invalidIsoCount }
        Save-Report -Report $Report
        Write-Log "$invalidIsoCount ISO file(s) failed header validation. Re-run without -ValidateIsoHeaders to skip this check." "ERROR"
        exit 40
    }
    if ($VerifyHashes) {
        Write-Log 'Pre-run SHA-256...'
        $pre = @(Get-FileHashes -Files $isoFiles)
        $preLookup = New-IsoLookup -Items $pre
        for ($i = 0; $i -lt $isoReport.Count; $i++) {
            $h = if ($preLookup.ContainsKey($isoReport[$i].key)) { $preLookup[$isoReport[$i].key] } else { $null }
            if ($h) { $isoReport[$i].pre_sha256 = $h.SHA256 }
        }
    }
    $Report.isos = $isoReport.ToArray()
    Save-State 'pre-snapshot' @{ isoCount=$isoReport.Count; hashing=[bool]$VerifyHashes; headerValidation=[bool]$ValidateIsoHeaders }

    # -- SISOU execution with retry / backoff -------------------------------
    $finalResult = $null
    $maxAttempts = [Math]::Max(1, $RetryCount)

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        if (Test-Cancellation) {
            Write-Log 'Cancellation requested before sisou attempt started.' "WARNING"
            $finalResult = @{ ExitCode=-3; StdOut=''; StdErr=''; LogFile=$null; Cancelled=$true }
            break
        }

        Write-Log "sisou attempt $attempt / $maxAttempts"
        $Report.sisou.attempts = $attempt

        $res = Invoke-Sisou -PythonExe $py -VentoyRoot $ventoy `
                            -TimeoutSec $TimeoutSeconds -ExtraArgs $SisouArgs

        $Report.sisou.exitcode = $res.ExitCode
        $Report.sisou.logfile  = $res.LogFile
        # Store only a capped tail of output to avoid huge report files
        $maxChars = 4096
        $Report.sisou.stdout_tail = if ($res.StdOut.Length -gt $maxChars) {
            '...' + $res.StdOut.Substring($res.StdOut.Length - $maxChars) } else { $res.StdOut }
        $Report.sisou.stderr_tail = if ($res.StdErr.Length -gt $maxChars) {
            '...' + $res.StdErr.Substring($res.StdErr.Length - $maxChars) } else { $res.StdErr }

        Write-Log "sisou exit code: $($res.ExitCode)"

        if ($res.Cancelled -or $res.ExitCode -eq -3 -or (Test-Cancellation)) {
            Write-Log 'Run cancelled by user. No retry will be attempted.' "WARNING"
            $finalResult = $res
            break
        }

        if ($res.ExitCode -eq 0) { $finalResult = $res; break }

        Write-Log "Non-zero exit ($($res.ExitCode))." "WARNING"
        if ($attempt -lt $maxAttempts) {
            $backoff = [Math]::Min(300, [Math]::Pow(2, $attempt))
            Write-Log "Retry in $([int]$backoff)s..."
            if (-not (Wait-CancellableSleep -Seconds ([int]$backoff))) {
                Write-Log 'Retry wait cancelled by user.' "WARNING"
                $finalResult = @{ ExitCode=-3; StdOut=$res.StdOut; StdErr=$res.StdErr; LogFile=$res.LogFile; Cancelled=$true }
                break
            }
        } else { $finalResult = $res }
    }

    if ($null -eq $finalResult) { Write-Log 'No result from sisou.' "ERROR"; exit 30 }

    if ($finalResult.Cancelled -or $finalResult.ExitCode -eq -3 -or (Test-Cancellation)) {
        $Report.cancelled = $true
        $Report.cancelReason = if ($Script:CancellationReason) { $Script:CancellationReason } else { 'User cancellation' }
        $Report.sisou.exitcode = -3
        Save-State 'cancelled' @{ reason=$Report.cancelReason; attempts=$Report.sisou.attempts }
        Save-Report -Report $Report
        Write-Log "Cancelled: $($Report.cancelReason)" "WARNING"
        exit 130
    }

    # -- Post-run status mapping -------------------------------------------
    $isoFilesPost = @(Get-IsoFiles -Root $ventoy)
    $postHashes   = @()
    if ($VerifyHashes) {
        Write-Log 'Post-run SHA-256...'
        $postHashes = @(Get-FileHashes -Files $isoFilesPost)
    }
    $postFileLookup = New-IsoLookup -Items $isoFilesPost
    $postHashLookup = New-IsoLookup -Items $postHashes

    for ($i = 0; $i -lt $Report.isos.Count; $i++) {
        $entry    = $Report.isos[$i]
        $postFile = if ($postFileLookup.ContainsKey($entry.key)) { $postFileLookup[$entry.key] } else { $null }
        if (-not $postFile) { $Report.isos[$i].status = 'removed'; continue }

        $newMtime = $postFile.LastWriteTimeUtc.ToString('o')
        $newSize  = $postFile.Length
        $Report.isos[$i].last_write_utc_post = $newMtime
        $Report.isos[$i].size_post           = $newSize

        if ($VerifyHashes) {
            $ph = if ($postHashLookup.ContainsKey($entry.key)) { $postHashLookup[$entry.key] } else { $null }
            if ($ph) {
                $Report.isos[$i].post_sha256 = $ph.SHA256
                $Report.isos[$i].status = if ($ph.Error) { 'hash-error' }
                    elseif ($null -ne $ph.SHA256 -and $null -ne $entry.pre_sha256 -and
                            $ph.SHA256 -ne $entry.pre_sha256) { 'updated' }
                    elseif ($null -eq $entry.pre_sha256) { 'hash-error' }
                    else { 'unchanged' }
            }
        } else {
            $Report.isos[$i].status = if ($newSize -ne $entry.size -or
                                          $newMtime -ne $entry.last_write_utc) { 'updated' }
                                      else { 'unchanged' }
        }
    }

    # Newly appeared ISOs (added by sisou)
    $reportNameLookup = New-IsoLookup -Items $Report.isos
    foreach ($pf in $isoFilesPost) {
        if (-not $reportNameLookup.ContainsKey($pf.FullName)) {
            $arr = New-Object 'System.Collections.Generic.List[hashtable]'
            foreach ($x in $Report.isos) { $arr.Add($x) }
            $arr.Add(@{
                name                = $pf.Name
                key                 = $pf.FullName
                size                = $null; last_write_utc=$null
                pre_sha256          = $null; post_sha256=$null
                size_post           = $pf.Length
                last_write_utc_post = $pf.LastWriteTimeUtc.ToString('o')
                status              = 'added'
            })
            $Report.isos = $arr.ToArray()
        }
    }

    # -- Pair removed/added ISOs that represent version updates (heuristic) --
    $remCandidates = New-Object 'System.Collections.Generic.List[hashtable]'
    $addCandidates = New-Object 'System.Collections.Generic.List[hashtable]'
    foreach ($e in $Report.isos) {
        if ($e.status -eq 'removed') { $remCandidates.Add($e) }
        if ($e.status -eq 'added')   { $addCandidates.Add($e) }
    }
    $claimedAdds   = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
    $namesToRemove = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rem in $remCandidates) {
        $remBase = Get-IsoBaseName $rem.name
        if ($remBase.Length -lt 5) { continue }
        $matchedAdd = $addCandidates |
            Where-Object { -not $claimedAdds.Contains($_.key) -and
                           [IO.Path]::GetDirectoryName($_.key) -eq [IO.Path]::GetDirectoryName($rem.key) -and
                           (Get-IsoBaseName $_.name) -eq $remBase } |
            Select-Object -First 1
        if ($matchedAdd) {
            $claimedAdds.Add($matchedAdd.key) | Out-Null
            $namesToRemove.Add($rem.key)      | Out-Null
            $matchedAdd.status   = 'updated'
            $matchedAdd.old_name = $rem.name
        }
    }
    if ($namesToRemove.Count -gt 0) {
        $Report.isos = @($Report.isos | Where-Object { -not $namesToRemove.Contains($_.key) })
    }

    # -- Summary ------------------------------------------------------------
    $updated   = @($Report.isos | Where-Object { $_.status -eq 'updated' }).Count
    $added     = @($Report.isos | Where-Object { $_.status -eq 'added'   }).Count
    $removed   = @($Report.isos | Where-Object { $_.status -eq 'removed' }).Count
    $unchanged = @($Report.isos | Where-Object { $_.status -eq 'unchanged' }).Count
    Write-Log "Summary: updated=$updated  added=$added  removed=$removed  unchanged=$unchanged"

    $upstreamErrors = 0
    if ($finalResult.LogFile -and (Test-Path -LiteralPath $finalResult.LogFile)) {
        $upstreamErrors = @(Select-String -LiteralPath $finalResult.LogFile -Pattern ' - ERROR - ').Count
    }
    $Report.sisou.updaterErrors = $upstreamErrors
    Save-State $(if ($finalResult.ExitCode -eq 0 -and $upstreamErrors -eq 0) { 'completed' } else { 'failed' }) @{ sisouExit=$finalResult.ExitCode; updaterErrors=$upstreamErrors }
    Save-Report -Report $Report

    if ($finalResult.ExitCode -ne 0) {
        Write-Log "sisou finished with exit code $($finalResult.ExitCode)." "ERROR"
        exit 30
    }

    if ($upstreamErrors -gt 0) {
        Write-Log "SISOU exited successfully but logged $upstreamErrors updater error(s). See its local log." 'ERROR'
        exit 30
    }

    Write-Log 'Done.'
    exit 0

} catch {
    if (Test-Cancellation) {
        $Report.cancelled = $true
        $Report.cancelReason = if ($Script:CancellationReason) { $Script:CancellationReason } else { $_.Exception.Message }
        Save-State 'cancelled' @{ reason=$Report.cancelReason; attempts=$Report.sisou.attempts }
        try { Save-Report -Report $Report } catch { }
        Write-Log "Cancelled: $($Report.cancelReason)" "WARNING"
        exit 130
    }
    $errMsg = 'Unhandled exception: ' + $_.Exception.Message + [System.Environment]::NewLine + $_.ScriptStackTrace
    Write-Log $errMsg "ERROR"
    if ($Script:RunLock) { try { Save-Report -Report $Report } catch { } }
    exit 99
} finally {
    # Pause / offer menu return before the window closes
    [Console]::remove_CancelKeyPress($Script:CancelHandler)
    Stop-ChildProcess $Script:ActiveProc
    if ($Script:RunLock) { $Script:RunLock.Dispose(); $Script:RunLock = $null }
    if ($Script:PauseAtExit) {
        Write-Host ''
        if ($Script:FromMenu) {
            Write-Host '  [M] Back to menu    [Enter] Close' -ForegroundColor DarkGray
            $c = (Read-Host '  Choice').Trim().ToUpper()
            if ($c -eq 'M') {
                # Re-invoke self with no args in the same process; menu will be shown again.
                # Parent is still explorer, so PauseAtExit will re-detect correctly.
                $menuParameters = Get-MenuParameters $PSBoundParameters
                & $PSCommandPath @menuParameters
            }
        } else {
            Write-Host 'Press Enter to close this window...' -ForegroundColor DarkGray
            $null = Read-Host
        }
    }
}
