# Version: 2.1

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
    Path to a sisou config.toml, passed via -c.

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

.PARAMETER VerifyHashes
    Compute SHA-256 of every ISO before and after the run. Opt-in because reading
    every byte of 30+ ISOs on a USB stick is slow and causes unnecessary flash wear.

.PARAMETER SkipPipUpgrade
    Skip the "pip install --upgrade sisou" step. Use when offline or on a metered
    connection where sisou is already installed at the required version.

.PARAMETER DryRun
    Show what would be done without running sisou.

.PARAMETER NonInteractive
    No prompts. Use first Ventoy drive found, or exit 10 if none.

.PARAMETER UseWinget
    Force the winget / system-Python path even when a managed runtime is available.

.PARAMETER Help
    Print usage and exit 0.

.PARAMETER SisouArgs
    Extra arguments forwarded verbatim to sisou (append after "--" on the command line).

.EXAMPLE
    pwsh -File sisou-runner.ps1
.EXAMPLE
    pwsh -File sisou-runner.ps1 -Drive F: -DryRun
.EXAMPLE
    pwsh -File sisou-runner.ps1 -NonInteractive -LogLevel DEBUG
.EXAMPLE
    pwsh -File sisou-runner.ps1 -SkipPipUpgrade -- --some-sisou-flag

.NOTES
    Requires PowerShell 5.1+. On PS 7+, -VerifyHashes hashing runs in parallel.

.EXIT CODES
    0   Success
   10   No Ventoy drive found / invalid selection
   20   Python runtime bootstrap failure
   30   SISOU returned non-zero exit code
   40   Pre-flight validation failure
   50   sisou pip install failure
   99   Unexpected / unhandled error
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]  $Drive,
    [string]  $ConfigFile,
    [ValidateSet('DEBUG','INFO','WARNING','ERROR','CRITICAL')]
    [string]  $LogLevel,
    [string]  $LogDir,
    [int]     $RetryCount     = 2,
    [int]     $TimeoutSeconds = 3600,
    [int]     $HashThrottle   = 4,
    [switch]  $VerifyHashes,
    [switch]  $SkipPipUpgrade,
    [switch]  $DryRun,
    [switch]  $NonInteractive,
    [switch]  $UseWinget,
    [switch]  $Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $SisouArgs
)

$ScriptVersion = '2.1'

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
  pwsh -File sisou-runner.ps1 [OPTIONS] [-- SISOU_ARGS]

OPTIONS
  -Drive <letter>         Ventoy drive letter. Auto-detected if omitted.
  -ConfigFile <path>      sisou config.toml, passed via -c.
  -LogLevel <level>       SISOU log verbosity: DEBUG|INFO|WARNING|ERROR|CRITICAL.
  -LogDir <path>          Log directory (default: %ProgramData%\SISOU\logs).
  -RetryCount <n>         SISOU attempts on failure (default: 2).
  -TimeoutSeconds <n>     Per-attempt timeout in seconds (default: 3600).
  -HashThrottle <n>       Parallel SHA-256 threads on PS7+ with -VerifyHashes (default: 4).
  -VerifyHashes           SHA-256 each ISO before and after - opt-in, slow on USB.
  -SkipPipUpgrade         Skip "pip install --upgrade sisou" (offline / already current).
  -DryRun                 Preview only; sisou is not executed.
  -NonInteractive         No prompts; fail fast if input is missing.
  -UseWinget              Force winget / system-Python path.
  -Help                   Show this help.
  -- <args>               Extra args forwarded verbatim to sisou.

EXIT CODES
   0  Success
  10  No Ventoy drive found
  20  Python runtime bootstrap failed
  30  sisou returned non-zero
  40  Pre-flight validation failure
  50  sisou pip install failed
  99  Unexpected error

SISOU KNOWN LIMITATIONS
  - Some updaters may fail with network errors (transient; the runner retries).
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
$Script:FromMenu    = $false  # true when user picked an option from the launch menu

###############################################################################
# CTRL+C / SIGINT HANDLER
# Registered once at startup. Kills any in-flight child process cleanly.
###############################################################################
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($Script:ActiveProc -and -not $Script:ActiveProc.HasExited) {
        try { $Script:ActiveProc.Kill() } catch { }
    }
}
# ConsoleCancelEventHandler - fires before the process exits on Ctrl+C
try { [Console]::TreatControlCAsInput = $false } catch { }
try {
    [Console]::add_CancelKeyPress([ConsoleCancelEventHandler] {
        param($s, $e)
        $null = $s  # sender unused
        $e.Cancel = $true   # prevent immediate process kill; we handle it
        if ($Script:ActiveProc -and -not $Script:ActiveProc.HasExited) {
            Write-Host ''
            Write-Host '[Ctrl+C] Stopping sisou gracefully...' -ForegroundColor Yellow
            try { $Script:ActiveProc.Kill() } catch { }
        }
    })
} catch { }

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
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $Script:StateFile -Encoding UTF8
}

function Save-Report {
    param([hashtable] $Report)
    $Report.completed = (Get-Date).ToString('o')
    try {
        $Report | ConvertTo-Json -Depth 10 |
            Set-Content -Path $Script:ReportPath -Encoding UTF8
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
        $p.WaitForExit(5000) | Out-Null
        $raw = ($p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()).Trim()
        if ($raw -match 'Python\s+(\d+\.\d+\.\d+)') {
            return [version] $Matches[1]
        }
    } catch { }
    return $null
}

###############################################################################
# PYTHON - BEST SYSTEM PYTHON (>=3.12, highest wins)
###############################################################################
function Select-BestSystemPython {
    $candidates = New-Object 'System.Collections.Generic.List[string]'

    # PATH entries
    foreach ($name in 'python','python3','py') {
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

    $best = $null; $bestVer = $null
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
        if ($null -eq $bestVer -or $ver -gt $bestVer) { $best = $exe; $bestVer = $ver }
    }

    if ($best) { Write-Log "Selected Python $bestVer" }
    else       { Write-Log 'No system Python >=3.12 found.' "DEBUG" }
    return $best
}

###############################################################################
# PYTHON - MANAGED (EMBEDDED) RUNTIME
###############################################################################
function Get-ManagedRuntime {
    $root    = Get-InstallRoot
    $pyDir   = Join-Path $root 'runtime\python'
    $venvDir = Join-Path $root 'runtime\venv'
    $venvPy  = Join-Path $venvDir 'Scripts\python.exe'

    if (Test-Path $venvPy) {
        Write-Log 'Managed runtime already present.'
        return $venvPy
    }

    Write-Log 'Downloading Python 3.12 installer for managed runtime...'
    try {
        if (-not (Test-Path (Split-Path $pyDir -Parent))) {
            New-Item -Path (Split-Path $pyDir -Parent) -ItemType Directory -Force | Out-Null
        }
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

        Write-Log 'Creating venv...'
        & $pyExe -m venv $venvDir
        if (-not (Test-Path $venvPy)) { throw "venv python.exe missing after creation" }

        & $venvPy -m pip install --upgrade pip --quiet --disable-pip-version-check
        & $venvPy -m pip install --upgrade sisou --quiet
        if ($LASTEXITCODE -ne 0) { throw "pip install sisou failed" }

        Write-Log 'Managed runtime ready.'
        return $venvPy
    } catch {
        Write-Log "Managed runtime bootstrap failed: $_" "ERROR"
        return $null
    }
}

###############################################################################
# PYTHON - WINGET FALLBACK
###############################################################################
function Install-PythonViaWinget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log 'winget not available.' "WARNING"
        return $false
    }
    foreach ($id in 'Python.Python.3.12','Python.Python.3.11','Python.Python.3','Python.Python') {
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
    try {
        # --no-input suppresses pip's interactive prompts
        # 2>&1 redirect means pip [notice] lines go to stdout where we can filter them
        $raw = & $PythonExe -m pip install --upgrade sisou --quiet `
                            --no-input --disable-pip-version-check --no-warn-script-location 2>&1
        if ($LASTEXITCODE -ne 0) { throw "pip exited $LASTEXITCODE" }
        # Surface any non-notice lines (genuine warnings/errors) as DEBUG
        $raw | Where-Object { $_ -and $_ -notmatch '^\[notice\]' } |
               ForEach-Object { Write-Log $_ "DEBUG" }
        return $true
    } catch {
        Write-Log "pip install sisou failed: $_" "ERROR"
        return $false
    }
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
    $drive = $Root.TrimEnd('\').TrimEnd('/')
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
                    $m = (Read-Host 'Drive letter or path (e.g. E:)').Trim()
                    if (Test-IsVentoy $m) { return $m }
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
        $items = @(Get-ChildItem -Path "$Root\" -Recurse -Filter '*.iso' -File `
                                 -Force -ErrorAction SilentlyContinue)
        Write-Log "Found $($items.Count) ISO file(s)."
        return $items
    } catch {
        Write-Log "ISO scan failed: $_" "ERROR"
        return @()
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
                [PSCustomObject]@{ Name=$f.Name; Size=$f.Length; SHA256=$h.Hash; Error=$null }
            } catch {
                [PSCustomObject]@{ Name=$f.Name; Size=$f.Length; SHA256=$null; Error=$_.Exception.Message }
            }
        } -ThrottleLimit $ht
    } else {
        foreach ($f in $Files) {
            try {
                $h = Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop
                $results += [PSCustomObject]@{ Name=$f.Name; Size=$f.Length; SHA256=$h.Hash; Error=$null }
            } catch {
                $results += [PSCustomObject]@{ Name=$f.Name; Size=$f.Length; SHA256=$null; Error=$_.Exception.Message }
            }
        }
    }
    return $results
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

###############################################################################
# SISOU INVOCATION
# stdout  - async line reader (sisou log output is always \n-terminated)
# stderr  - synchronous Peek/Read poll (\r-based tqdm progress bars render correctly)
# Ctrl+C  - $Script:ActiveProc allows the exit handler to kill the process
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

    # --- Argumenten opbouwen (jouw originele logica) ---
    $hasF = @($ExtraArgs | Where-Object { $_ -eq '-f' -or $_ -eq '--log-file'    }).Count -gt 0
    $hasL = @($ExtraArgs | Where-Object { $_ -eq '-l' -or $_ -eq '--log-level'   }).Count -gt 0
    $hasC = @($ExtraArgs | Where-Object { $_ -eq '-c' -or $_ -eq '--config-file' }).Count -gt 0

    $argList = New-Object 'System.Collections.Generic.List[string]'
    $argList.Add('-m'); $argList.Add('sisou'); $argList.Add($VentoyRoot)
    if ($LogLevel  -and -not $hasL) { $argList.Add('-l'); $argList.Add($LogLevel)  }
    if (-not $hasF)                 { $argList.Add('-f'); $argList.Add($sisouLog)   }
    if (-not [string]::IsNullOrWhiteSpace($ConfigFile) -and -not $hasC) {
        $argList.Add('-c'); $argList.Add($ConfigFile)
    }
    foreach ($a in $ExtraArgs) { $argList.Add($a) }

    $quotedArgs = ($argList | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    }) -join ' '

    Write-Log "Launching: sisou $VentoyRoot"

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
            $line = $null
            
            # --- STDOUT (Normale Logs) ---
            while ($stdOutQueue.TryDequeue([ref]$line)) {
                [void]$stdOutBuf.AppendLine($line)
                # Als er nog een voortgangsbalk stond, zet die op een nieuwe regel
                if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }
                Write-Host $line
            }

            # --- STDERR (Progress Bars & Filtering) ---
            while ($stdErrQueue.TryDequeue([ref]$line)) {
                # Fix 2: Extra filter voor hardnekkige UserWarnings
                if ($line -match 'UserWarning:' -or $line -match 'warnings\.warn') { continue }

                [void]$stdErrBuf.AppendLine($line)
                
                # Detecteer tqdm progress bar (bv. "ubuntu.iso: 50%|###")
                if ($line -match '^(.+?):\s+\d+%.*\|') {
                    $currentFile = $Matches[1]

                    # Fix 3: Als we wisselen van ISO, sluit de vorige netjes af met een Enter
                    if ($null -ne $lastFileName -and $currentFile -ne $lastFileName) {
                        Write-Host "" 
                    }
                    $lastFileName = $currentFile

                    $disp = if ($line.Length -ge $conW) { $line.Substring(0, $conW - 1) } else { $line.PadRight($conW - 1) }
                    Write-Host -NoNewline "`r$disp" -ForegroundColor DarkGray
                } 
                elseif ($line -match '100%\|') {
                    # Voltooid: schrijf de 100% regel definitief weg
                    Write-Host "`r$($line.PadRight($conW - 1))" -ForegroundColor DarkGray
                    $lastFileName = $null
                }
                else {
                    # Andere stderr (echte errors)
                    if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }
                    Write-Host $line -ForegroundColor Red
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
                        $lvl = $Matches[1]; $msg = $Matches[2]
                        if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                        $lc = switch ($lvl) { 'WARNING' { 'Yellow' } 'ERROR' { 'DarkRed' } default { 'DarkCyan' } }
                        Write-Host "[sisou][$lvl] $msg" -ForegroundColor $lc
                        $lastLogWasError = ($lvl -eq 'ERROR')
                    } elseif ($lastLogWasError -and $logLine.Trim() -ne '') {
                        if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                        Write-Host "         $logLine" -ForegroundColor DarkRed
                    } elseif ($logLine.Trim() -eq '') {
                        $lastLogWasError = $false
                    }
                }
            }

            Start-Sleep -Milliseconds 50
            
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
                Write-Log "Timeout (${TimeoutSec}s) - killing sisou." "WARNING"
                try { $proc.Kill() } catch { }
                $proc.WaitForExit(5000) | Out-Null
                return @{ ExitCode=-2; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString(); LogFile=$sisouLog }
            }
        }

        $proc.WaitForExit()

        # Laatste buffers legen
        while ($stdOutQueue.TryDequeue([ref]$line)) { 
            if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }; Write-Host $line 
        }
        while ($stdErrQueue.TryDequeue([ref]$line)) {
            if ($line -match 'UserWarning:' -or $line -match 'warnings\.warn') { continue }
            if ($null -ne $lastFileName) { Write-Host ""; $lastFileName = $null }
            Write-Host $line -ForegroundColor DarkGray
        }
        if ($logReader) {
            $logLine = $null
            while ($null -ne ($logLine = $logReader.ReadLine())) {
                if ($logLine -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+ - (INFO|WARNING|ERROR) - (.+)$') {
                    $lvl = $Matches[1]; $msg = $Matches[2]
                    if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                    $lc = switch ($lvl) { 'WARNING' { 'Yellow' } 'ERROR' { 'DarkRed' } default { 'DarkCyan' } }
                    Write-Host "[sisou][$lvl] $msg" -ForegroundColor $lc
                    $lastLogWasError = ($lvl -eq 'ERROR')
                } elseif ($lastLogWasError -and $logLine.Trim() -ne '') {
                    if ($null -ne $lastFileName) { Write-Host ''; $lastFileName = $null }
                    Write-Host "         $logLine" -ForegroundColor DarkRed
                } elseif ($logLine.Trim() -eq '') {
                    $lastLogWasError = $false
                }
            }
        }

        Write-Host "" # Eindig altijd met een schone regel

        return @{ ExitCode=$proc.ExitCode; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString(); LogFile=$sisouLog }

    } catch {
        return @{ ExitCode=-1; StdOut=$stdOutBuf.ToString(); StdErr=$stdErrBuf.ToString() + $_; LogFile=$sisouLog }
    } finally {
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
}

###############################################################################
# INTERACTIVE LAUNCH MENU
# Shown when the script is invoked with no arguments, e.g. via right-click
# "Run with PowerShell" or a plain desktop shortcut.
###############################################################################
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
            Write-Host '  No arguments detected. What would you like to do?' -ForegroundColor White
            Write-Host ''
            Write-Host '  [1]  Run            Auto-detect Ventoy drive and update ISOs' -ForegroundColor Green
            Write-Host '  [2]  Dry run        Preview what would be updated (no changes)' -ForegroundColor Cyan
            Write-Host '  [3]  Debug run      Same as Run, with verbose DEBUG logging' -ForegroundColor Yellow
            Write-Host '  [4]  Help           Show all parameters and exit codes' -ForegroundColor Gray
            Write-Host '  [Q]  Quit'
            Write-Host ''
            Write-Host '  Tip: pass arguments to skip this menu, e.g.  .\sisou-runner.ps1 -DryRun' -ForegroundColor DarkGray
            Write-Host ''
            $showBanner = $false
        }
        $c = (Read-Host '  Choice (default: 1)').Trim().ToUpper()
        switch ($c) {
            ''  { return @{ Action='run'; DryRun=$false; LogLevel=$null   } }
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
            'Q' { return @{ Action='quit' } }
            default { Write-Host '  Please enter 1, 2, 3, 4, or Q.' -ForegroundColor Yellow }
        }
    }
}

###############################################################################
# ENTRY POINT
###############################################################################
# Report intentionally omits full paths (GDPR / privacy).
# ISO entries use filename only; drive letter is stored as a single character.
$Report = @{
    started  = (Get-Date).ToString('o')
    drive    = $null          # drive letter only, e.g. "F"
    mode     = if ($Script:DryRun) { 'dry-run' } else { 'live' }
    runtime  = @{ type=''; pythonVersion='' }
    isos     = @()
    sisou    = @{ exitcode=$null; logfile=$null; attempts=0; args=$SisouArgs }
    completed = $null
}

try {
    # -- Interactive launch menu (no-argument invocation) ------------------
    if ($PSBoundParameters.Count -eq 0 -and -not $NonInteractive -and [Environment]::UserInteractive) {
        $menu = Show-LaunchMenu
        switch ($menu.Action) {
            'quit' {
                $Script:PauseAtExit = $false   # user already interacted; no double-prompt
                exit 0
            }
            'run' {
                $Script:PauseAtExit = $true    # menu -> always a direct-launch window
                $Script:FromMenu = $true
                if ($menu.DryRun)   { $Script:DryRun = $true }
                if ($menu.LogLevel) { $LogLevel = $menu.LogLevel }
            }
        }
    }

    Initialize-Logging
    Write-Log "sisou-runner.ps1 v$ScriptVersion starting (PowerShell $($PSVersionTable.PSVersion))"

    Assert-Inputs

    # -- Runtime selection -------------------------------------------------
    $py = $null

    if (-not $UseWinget) {
        $py = Select-BestSystemPython
        if ($py) {
            $Report.runtime.type = 'system'
            if (-not (Install-Sisou -PythonExe $py)) { exit 50 }
        }
    }

    if (-not $py) {
        Write-Log 'Trying managed (embedded) Python runtime...'
        $Report.runtime.type = 'managed'
        $py = Get-ManagedRuntime
    }

    if (-not $py) {
        Write-Log 'Managed runtime failed; trying winget...' "WARNING"
        $Report.runtime.type = 'winget-fallback'
        if (-not (Install-PythonViaWinget)) {
            Write-Log 'No usable Python runtime available.' "ERROR"; exit 20
        }
        # Refresh PATH so newly installed Python is visible
        $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH','Machine') + ';' +
                    [System.Environment]::GetEnvironmentVariable('PATH','User')
        $py = Select-BestSystemPython
        if (-not $py) {
            Write-Log 'Python not found in PATH after winget install. Open a new shell and retry.' "ERROR"
            exit 20
        }
        if (-not (Install-Sisou -PythonExe $py)) { exit 50 }
    }

    $pyVer = Get-PythonVersion -Exe $py
    $Report.runtime.pythonVersion = if ($pyVer) { $pyVer.ToString() } else { 'unknown' }
    Write-Log "Python $($Report.runtime.pythonVersion) ($($Report.runtime.type))"

    # -- Ventoy selection --------------------------------------------------
    $ventoy       = Select-VentoyDrive
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
            Write-Host "Python : $($Report.runtime.pythonVersion) ($($Report.runtime.type))" -ForegroundColor Cyan
            Write-Host "ISOs   : $($files.Count) file(s) found" -ForegroundColor Cyan
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
            Write-Host "  1. pip install --upgrade sisou" -ForegroundColor Gray
            Write-Host "  2. python -m sisou $ventoy$(if ($LogLevel) { " -l $LogLevel" } else { '' })$(if ($ConfigFile) { " -c $ConfigFile" } else { '' })" -ForegroundColor Gray
            if ($RetryCount -gt 1) {
                Write-Host "  3. Retry up to $($RetryCount - 1) time(s) on failure (backoff: 2s, 4s, ...)" -ForegroundColor Gray
            }
            Write-Host "  4. Write report to $Script:ReportPath" -ForegroundColor Gray
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

    # -- Validate drive + ISOs ---------------------------------------------
    if (-not $ventoy) { Write-Log 'No Ventoy drive.' "ERROR"; exit 10 }

    $isoFiles = @(Get-IsoFiles -Root $ventoy)
    if ($isoFiles.Count -eq 0) {
        Write-Log "No ISO files on $ventoy." "ERROR"; exit 40
    }

    # -- Pre-run snapshot (mtime + size; SHA-256 opt-in) --------------------
    $isoReport = New-Object 'System.Collections.Generic.List[hashtable]'
    foreach ($f in $isoFiles) {
        $isoReport.Add(@{
            name            = $f.Name          # filename only - no full path
            size            = $f.Length
            last_write_utc  = $f.LastWriteTimeUtc.ToString('o')
            pre_sha256      = $null
            post_sha256     = $null
            status          = 'pending'
        })
    }
    if ($VerifyHashes) {
        Write-Log 'Pre-run SHA-256...'
        $pre = @(Get-FileHashes -Files $isoFiles)
        for ($i = 0; $i -lt $isoReport.Count; $i++) {
            $h = $pre | Where-Object { $_.Name -eq $isoReport[$i].name } | Select-Object -First 1
            if ($h) { $isoReport[$i].pre_sha256 = $h.SHA256 }
        }
    }
    $Report.isos = $isoReport.ToArray()
    Save-State 'pre-snapshot' @{ isoCount=$isoReport.Count; hashing=[bool]$VerifyHashes }

    # -- SISOU execution with retry / backoff -------------------------------
    $finalResult = $null
    $maxAttempts = [Math]::Max(1, $RetryCount)

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
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

        if ($res.ExitCode -eq 0) { $finalResult = $res; break }

        Write-Log "Non-zero exit ($($res.ExitCode))." "WARNING"
        if ($attempt -lt $maxAttempts) {
            $backoff = [Math]::Min(300, [Math]::Pow(2, $attempt))
            Write-Log "Retry in $([int]$backoff)s..."
            Start-Sleep -Seconds $backoff
        } else { $finalResult = $res }
    }

    if ($null -eq $finalResult) { Write-Log 'No result from sisou.' "ERROR"; exit 30 }

    # -- Post-run status mapping -------------------------------------------
    $isoFilesPost = @(Get-IsoFiles -Root $ventoy)
    $postHashes   = @()
    if ($VerifyHashes) {
        Write-Log 'Post-run SHA-256...'
        $postHashes = @(Get-FileHashes -Files $isoFilesPost)
    }

    for ($i = 0; $i -lt $Report.isos.Count; $i++) {
        $entry    = $Report.isos[$i]
        $postFile = $isoFilesPost | Where-Object { $_.Name -eq $entry.name } | Select-Object -First 1
        if (-not $postFile) { $Report.isos[$i].status = 'removed'; continue }

        $newMtime = $postFile.LastWriteTimeUtc.ToString('o')
        $newSize  = $postFile.Length
        $Report.isos[$i].last_write_utc_post = $newMtime
        $Report.isos[$i].size_post           = $newSize

        if ($VerifyHashes) {
            $ph = $postHashes | Where-Object { $_.Name -eq $entry.name } | Select-Object -First 1
            if ($ph) {
                $Report.isos[$i].post_sha256 = $ph.SHA256
                $Report.isos[$i].status = if ($ph.Error) { 'hash-error' }
                    elseif ($null -ne $ph.SHA256 -and $null -ne $entry.pre_sha256 -and
                            $ph.SHA256 -ne $entry.pre_sha256) { 'updated' }
                    else { 'unchanged' }
            }
        } else {
            $Report.isos[$i].status = if ($newSize -ne $entry.size -or
                                          $newMtime -ne $entry.last_write_utc) { 'updated' }
                                      else { 'unchanged' }
        }
    }

    # Newly appeared ISOs (added by sisou)
    foreach ($pf in $isoFilesPost) {
        if (-not ($Report.isos | Where-Object { $_.name -eq $pf.Name })) {
            $arr = New-Object 'System.Collections.Generic.List[hashtable]'
            foreach ($x in $Report.isos) { $arr.Add($x) }
            $arr.Add(@{
                name                = $pf.Name
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
            Where-Object { -not $claimedAdds.Contains($_.name) -and
                           (Get-IsoBaseName $_.name) -eq $remBase } |
            Select-Object -First 1
        if ($matchedAdd) {
            $claimedAdds.Add($matchedAdd.name) | Out-Null
            $namesToRemove.Add($rem.name)      | Out-Null
            $matchedAdd.status   = 'updated'
            $matchedAdd.old_name = $rem.name
        }
    }
    if ($namesToRemove.Count -gt 0) {
        $Report.isos = @($Report.isos | Where-Object { -not $namesToRemove.Contains($_.name) })
    }

    # -- Summary ------------------------------------------------------------
    $updated   = @($Report.isos | Where-Object { $_.status -eq 'updated' }).Count
    $added     = @($Report.isos | Where-Object { $_.status -eq 'added'   }).Count
    $removed   = @($Report.isos | Where-Object { $_.status -eq 'removed' }).Count
    $unchanged = @($Report.isos | Where-Object { $_.status -eq 'unchanged' }).Count
    Write-Log "Summary: updated=$updated  added=$added  removed=$removed  unchanged=$unchanged"

    Save-State 'completed' @{ sisouExit=$finalResult.ExitCode }
    Save-Report -Report $Report

    if ($finalResult.ExitCode -ne 0) {
        Write-Log "sisou finished with exit code $($finalResult.ExitCode)." "ERROR"
        exit 30
    }

    Write-Log 'Done.'
    exit 0

} catch {
    $errMsg = 'Unhandled exception: ' + $_.Exception.Message + [System.Environment]::NewLine + $_.ScriptStackTrace
    Write-Log $errMsg "ERROR"
    try { Save-Report -Report $Report } catch { }
    exit 99
} finally {
    # Pause / offer menu return before the window closes
    if ($Script:PauseAtExit) {
        Write-Host ''
        if ($Script:FromMenu) {
            Write-Host '  [M] Back to menu    [Enter] Close' -ForegroundColor DarkGray
            $c = (Read-Host '  Choice').Trim().ToUpper()
            if ($c -eq 'M') {
                # Re-invoke self with no args in the same process; menu will be shown again.
                # Parent is still explorer, so PauseAtExit will re-detect correctly.
                & $PSCommandPath
            }
        } else {
            Write-Host 'Press Enter to close this window...' -ForegroundColor DarkGray
            $null = Read-Host
        }
    }
}