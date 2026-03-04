@{
    # Customize PSScriptAnalyzer rules for this interactive CLI/GUI script
    # We intentionally use Write-Host for colored, interactive output and
    # have internal state-changing helpers that aren't intended as public cmdlets.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSAvoidTrailingWhitespace',
        # All empty catch blocks are intentional defensive swallows (non-console hosts,
        # optional OS APIs). Adding noise statements would obscure the intent.
        'PSAvoidUsingEmptyCatchBlock',
        # Write-Log is an internal helper; the PS Core 6.1 cmdlet of the same name is
        # never used in this script and this is not a redistributable module.
        'PSAvoidOverwritingBuiltInCmdlets'
    )
}
