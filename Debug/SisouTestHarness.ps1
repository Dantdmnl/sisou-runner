#Requires -Version 5.1
param([string[]] $Functions)

$sourcePath = Join-Path $PSScriptRoot '..\sisou-runner.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw ($parseErrors | Out-String) }
foreach ($name in $Functions) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function: $name" }
    Set-Item -Path ("Function:script:" + $name) -Value $definition.Body.GetScriptBlock()
}
