v2.3 improves Windows runtime isolation, cancellation, reporting, and the
interactive menu. SISOU itself remains an upstream dependency, with its version
recorded separately in reports.

## Download and Run

Download **sisou-runner.ps1** from the assets below. No ZIP extraction is needed.
GitHub provides the asset's SHA-256 digest; there is no separate checksum download.

Run from the folder containing the script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1
```

Supports Windows PowerShell 5.1 and PowerShell 7; replace `powershell` with `pwsh`
for PowerShell 7. Press Enter or select **2** to preview; select **1** for a live
update. To preview a specific Ventoy drive:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1 -Drive F: -DryRun -NonInteractive
```

Python 3.12+ packages are managed in an isolated host environment. Install GnuPG
for signature verification where supported by the upstream updater. If the drive
has no `sisou.toml`, the first live run creates it and returns. Review its enabled
images before running again.

## What's New Since v2.2

- **Runtime isolation:** installs and repairs stay out of shared Python environments; the interpreter, imports, and pip dependencies are checked.
- **Menu improvements:** preview by default, drive/config selection, last-report summary, and preserved defaults. `-Menu` opens the menu with supplied options.
- **Process reliability:** concurrent output draining, correct Windows argument quoting, and process-tree cleanup with no retry after recognized cancellation.
- **Persistent data:** atomic state/report replacement and a runtime lock to prevent overlapping runs.
- **Accurate results:** duplicate ISO filenames are tracked independently; updater errors produce a partial-failure result even when SISOU exits zero.
- **Config/path fixes:** empty-drive support, absolute config paths, strict JSON types, TOML syntax checks, and drive shorthand normalization.
- **Regression tests:** menu entry-point coverage for the `Menu` switch collision, plus output, timeout, privacy, locking, and failure-path checks.

## Upgrade Notes

Replace the older runner script with this asset. Keep existing SISOU TOML configs
and ISOs; generating a new config is not required.

Enter now previews instead of starting downloads. JSON switches must be booleans
and numeric settings must be integers. Scan filters affect wrapper validation and
reporting, not which images SISOU downloads.

Reports omit raw arguments and child output tails; detailed diagnostics remain in
local logs. Exit codes include `30` for process/updater failures, `60` for a busy
runtime, and `130` for recognized user cancellation.

## Validation and Known Limits

All offline checks passed locally on PowerShell 5.1 and 7. GitHub Actions passed
both Windows test suites and static analysis:
[release CI run](https://github.com/Dantdmnl/sisou-runner/actions/runs/37793576464).
Live USB testing downloaded five ISOs before the run was stopped on request.

- Upstream mirror/parser failures and Microsoft download restrictions can affect individual images; a Rescuezilla parser error occurred during live testing.
- Physical Ctrl+C delivery depends on the terminal host; tests cover the native flag and cleanup path.
- Interrupted downloads are not guaranteed to resume.
- GPG trust and installer behavior are not fully covered by offline tests.
- Custom SISOU log-file overrides bypass generated-log monitoring; prefer the runner's logging options.

## Documentation

- [Usage, configuration, and exit codes](https://github.com/Dantdmnl/sisou-runner/blob/v2.3/README.md)
- [Example configurations](https://github.com/Dantdmnl/sisou-runner/tree/v2.3/Examples)
- [Full changelog](https://github.com/Dantdmnl/sisou-runner/blob/v2.3/CHANGELOG.md)
- [Compare v2.2 to v2.3](https://github.com/Dantdmnl/sisou-runner/compare/v2.2...v2.3)
