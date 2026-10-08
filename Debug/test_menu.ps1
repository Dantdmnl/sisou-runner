#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot\SisouTestHarness.ps1" -Functions @('Show-LaunchMenu','Show-RunnerSettings','ConvertTo-SisouPath','Get-MenuParameters')
$ScriptVersion = '2.3'
$script:Drive = $null
$script:ConfigFile = $null
$script:SettingsSavePath = 'runner-settings.json'
$script:SaveVisits = 0
$LogLevel = $null
$TimeoutSeconds = 0
$RetryCount = 2
[switch]$VerifyHashes = $false
[switch]$ValidateIsoHeaders = $false
[switch]$SkipPipUpgrade = $false
[switch]$SkipGpgCheck = $false
$script:Answers = New-Object 'System.Collections.Generic.Queue[string]'
$script:Cancelled = $false
$script:HelpVisits = 0
$script:ReportVisits = 0
function Clear-Host { }
function Write-Host { param($Object,$ForegroundColor) }
function Read-Host {
    param($Prompt)
    if ($script:Answers.Count -eq 0) { throw 'Menu unexpectedly asked for another answer.' }
    return $script:Answers.Dequeue()
}
function Test-Cancellation { return $script:Cancelled }
function Write-HelpText { $script:HelpVisits++ }
function Show-LastReport { $script:ReportVisits++ }
function Save-RunnerSettings { $script:SaveVisits++; return $script:SettingsSavePath }
function Invoke-MenuCase {
    param([string[]] $Answers)
    $script:Answers.Clear()
    foreach ($answer in $Answers) { $script:Answers.Enqueue($answer) }
    return Show-LaunchMenu
}
$result = Invoke-MenuCase -Answers @('')
if (-not $result.DryRun) { throw 'Enter did not default to preview.' }
$result = Invoke-MenuCase -Answers @('1')
if ($result.DryRun -or $result.Action -ne 'run') { throw 'Explicit run did not select a live run.' }
$result = Invoke-MenuCase -Answers @('3')
if ($result.DryRun -or $result.LogLevel -ne 'DEBUG') { throw 'Debug run selection failed.' }
$result = Invoke-MenuCase -Answers @('5','f:\','2')
if ($script:Drive -ne 'F:' -or -not $result.DryRun) { throw 'Drive selection was not retained.' }
$null = Invoke-MenuCase -Answers @('5','not-a-drive','Q')
if ($script:Drive -ne 'F:') { throw 'Invalid drive selection replaced the previous drive.' }
$config = Join-Path $PSScriptRoot '..\Examples\sisou-config.toml'
$null = Invoke-MenuCase -Answers @('6','C',$config,'B','Q')
if ($script:ConfigFile -ne (Resolve-Path $config).Path) { throw 'Config selection failed.' }
$null = Invoke-MenuCase -Answers @('6','C','missing-config-file.toml','B','Q')
if ($script:ConfigFile -ne (Resolve-Path $config).Path) { throw 'Missing config replaced the previous selection.' }
$null = Invoke-MenuCase -Answers @('4','','7','','Q')
if ($script:HelpVisits -ne 1 -or $script:ReportVisits -ne 1) { throw 'Menu views failed to return.' }
$null = Invoke-MenuCase -Answers @('5','','6','C','','B','Q')
if ($script:Drive -or $script:ConfigFile) { throw 'Auto/default selections did not reset.' }
$script:Cancelled = $true
$result = Show-LaunchMenu
if ($result.Action -ne 'cancel') { throw 'Menu ignored cancellation.' }
$script:Drive = 'F:'
$script:ConfigFile = $config
$script:Cancelled = $false
$null = Invoke-MenuCase -Answers @('6','1','7200','2','3','3','4','5','6','S','B','Q')
if ($script:SaveVisits -ne 1) { throw 'Settings save action was not invoked.' }
if ($TimeoutSeconds -ne 7200 -or $RetryCount -ne 3 -or -not $VerifyHashes -or
    -not $ValidateIsoHeaders -or -not $SkipPipUpgrade -or -not $SkipGpgCheck) {
    throw 'Runner settings were not applied.'
}
$null = Invoke-MenuCase -Answers @('6','1','10','2','0','B','Q')
if ($TimeoutSeconds -ne 7200 -or $RetryCount -ne 3) { throw 'Invalid settings replaced valid values.' }
$defaults = @{RetryCount=3;AdvancedConfigFile='runner.json';VerifyHashes=$true}
$restored = Get-MenuParameters $defaults
if (-not $restored.Menu -or $restored.Drive -ne 'F:' -or $restored.ConfigFile -ne $config -or
    $restored.RetryCount -ne 3 -or -not $restored.VerifyHashes -or $restored.ContainsKey('LogLevel')) {
    throw 'Returning to the menu lost defaults or forwarded an empty log level.'
}
if ($restored.TimeoutSeconds -ne 7200 -or -not $restored.SkipPipUpgrade) { throw 'Menu return lost edited settings.' }
if ($defaults.ContainsKey('Menu')) { throw 'Menu restoration mutated original bound defaults.' }
# Exercise the real entry-point handoff with the same typed parameters as the runner.
[switch]$Menu = $true
[switch]$DryRun = $false
$script:Cancelled = $false
$script:Answers.Enqueue('')
$assignment = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $node.Right.Extent.Text -eq 'Show-LaunchMenu'
}, $true)
if (-not $assignment) { throw 'Menu entry-point assignment was not found.' }
. ([scriptblock]::Create($assignment.Extent.Text))
if (-not $Menu.IsPresent) { throw 'Menu result overwrote the typed Menu parameter.' }
$selectionName = $assignment.Left.VariablePath.UserPath
$selection = (Get-Variable -Name $selectionName).Value
if ($selection.Action -ne 'run' -or -not $selection.DryRun) { throw 'Main-flow preview handoff failed.' }
$dispatch = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.SwitchStatementAst] -and
    $node.Condition.Extent.Text -eq ('$' + $selectionName + '.Action')
}, $true)
if (-not $dispatch) { throw 'Menu entry-point dispatch was not found.' }
. ([scriptblock]::Create($dispatch.Extent.Text))
if (-not $script:DryRun -or -not $script:FromMenu) { throw 'Menu preview was not applied to run state.' }
[Console]::WriteLine('[OK] Interactive menu contract checks passed.')
