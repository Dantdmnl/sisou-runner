# sisou-runner

A Windows PowerShell wrapper for [SuperISOUpdater (SISOU)](https://github.com/JoshuaVandaele/SuperISOUpdater) that manages ISO downloads and updates on a Ventoy drive.

**Current Version:** 2.3. See [CHANGELOG.md](CHANGELOG.md) for release notes and [GitHub Releases](https://github.com/Dantdmnl/sisou-runner/releases) for published downloads.

## Quick Start

Windows PowerShell 5.1 is included with Windows; PowerShell 7 is optional.

Download `sisou-runner.ps1` directly from the GitHub release assets; no ZIP
extraction or separate checksum file is needed. GitHub provides the asset digest.
Examples and the test suite are available in the repository.

Preview the drive first:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1 -Drive F: -DryRun -NonInteractive
```

Run SISOU:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1 -Drive F:
```

Run without parameters to open the interactive menu. Replace `powershell` with `pwsh` to use PowerShell 7.

The menu offers Run, Dry run, Debug run, Help, drive selection, TOML selection,
and a summary of the latest saved report. Enter selects a dry-run preview;
choose 1 explicitly to download/update images. Selected drive/config settings are
shown at the top, and Back to menu keeps supplied defaults and selections.

Use `-Menu` to open the menu with command-line or JSON defaults:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1 -Menu -Drive F: -AdvancedConfigFile .\Examples\runner-config.json
```

If the drive has no `sisou.toml`, the first live run creates `F:\sisou.toml` and returns without downloading images. An empty ISO collection is supported. Review the config's enabled updaters, then run again. The generated defaults can enable many large downloads.

## Requirements

- Windows and PowerShell 5.1 or later.
- A Ventoy data partition accessible to the current user.
- Python 3.12 or later. An installed interpreter can create the managed environment; otherwise the runner attempts Python installation.
- Internet access for installation, upgrades, and upstream image checks/downloads. `-SkipPipUpgrade` skips an existing SISOU installation's upgrade; it does not make image updates work offline.
- GnuPG for signature verification when supported by the upstream updater. The runner can locate it or offer installation through winget.
- Native torrent support may require the Microsoft Visual C++ Redistributable x64.

The one-command examples use a process-scoped execution policy. Organization policy can still prevent execution. Administrator rights are not required for every run; installation and protected storage may require elevation.

## Runtime and USB Storage

The runtime intentionally lives on the Windows host:

| Data                               | Default location                     |
| ---------------------------------- | ------------------------------------ |
| Managed SISOU environment          | `%ProgramData%\SISOU\runtime\venv`   |
| Downloaded Python, when needed     | `%ProgramData%\SISOU\runtime\python` |
| Wrapper and SISOU logs             | `%ProgramData%\SISOU\logs`           |
| Latest JSON report                 | `%ProgramData%\SISOU\report.json`    |
| Latest stage information           | `%ProgramData%\SISOU\state.json`     |
| Runtime lock                       | `%ProgramData%\SISOU\runner.lock`    |
| SISOU config without `-ConfigFile` | `<selected-drive>\sisou.toml`        |

The runner uses `%LocalAppData%\SISOU` when its ProgramData storage is not writable. `-LogDir` changes only the log directory.

Shared system Python packages are not modified. The managed environment is checked for a supported interpreter, successful SISOU imports, and consistent package requirements through `pip check`. Python library paths inherited through `PYTHONPATH` and `PYTHONHOME` are removed from child processes.

A custom TOML config controls its own download directories, resolved relative to that config's directory. Passing a config stored on the host can therefore save images on the host. The runner's ISO snapshot still scans the selected Ventoy drive; it is not a report of unrelated output directories.

The lock prevents overlapping runner processes from changing the same runtime and reports. It is released when the process exits. The file may remain present; its existence alone does not mean a run is active.

## Configuration

There are two independent configuration files:

| File        | Purpose                                                                           |
| ----------- | --------------------------------------------------------------------------------- |
| Runner JSON | Runtime setup, retries, scanning, hashing, and wrapper defaults                   |
| SISOU TOML  | Enabled image families, editions, architectures, naming, and download directories |

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1 -Drive F: -AdvancedConfigFile .\Examples\runner-config.json
```

Explicit command-line parameters override JSON defaults. Switch values must be JSON booleans; numeric settings must be integers in their allowed ranges. Unknown JSON options produce a warning and are ignored. The runner validates TOML syntax before download attempts and removes a UTF-8 BOM when found.

[Examples/runner-config.json](Examples/runner-config.json) contains runner defaults. [Examples/sisou-config.toml](Examples/sisou-config.toml) enables Ubuntu as a small starting selection. Place an adapted TOML on the USB drive before using it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sisou-runner.ps1 -Drive F: -ConfigFile "F:\sisou.toml"
```

## Options

Run `powershell -File .\sisou-runner.ps1 -Help` for built-in help.

| Option                                      | Behavior / default                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------------------ |
| `-Drive`                                    | Ventoy drive; accepts `F`, `F:`, or `F:\`. Auto-detected when omitted.               |
| `-ConfigFile`                               | SISOU TOML path, passed as its positional config argument.                           |
| `-AdvancedConfigFile`                       | Runner JSON defaults file.                                                           |
| `-LogLevel`                                 | SISOU verbosity: DEBUG, INFO, WARNING, ERROR, CRITICAL.                              |
| `-LogDir`                                   | Override the directory for local diagnostic logs.                                    |
| `-RetryCount`                               | Total attempts, including the first; default 2, minimum 1.                           |
| `-TimeoutSeconds`                           | Per-attempt timeout; default 3600, minimum 30 seconds.                               |
| `-IsoScanDepth`                             | Scan subfolder depth; default -1 (unlimited), 0 for drive root only.                 |
| `-IncludeIsoPattern` / `-ExcludeIsoPattern` | Wildcard filters for wrapper ISO discovery.                                          |
| `-VerifyHashes`                             | Compare SHA-256 before/after; disabled by default.                                   |
| `-HashThrottle`                             | Parallel hash workers on PowerShell 7; default 4, minimum 1.                         |
| `-ValidateIsoHeaders`                       | Check the ISO-9660 `CD001` signature before running SISOU.                           |
| `-SkipPipUpgrade`                           | Skip upgrading SISOU in an existing managed environment.                             |
| `-InstallGpg`                               | Attempt winget installation if GnuPG is missing.                                     |
| `-SkipGpgCheck`                             | Skip the GnuPG preflight.                                                            |
| `-DryRun`                                   | Preview local discovery/actions; do not execute SISOU or install packages.           |
| `-NonInteractive`                           | Suppress prompts; use the first detected Ventoy candidate.                           |
| `-UseWinget`                                | Ensure supported Python via the winget route; SISOU still uses a managed venv.       |
| `-SisouArgs`                                | Additional native SISOU arguments; only use flags supported by your installed SISOU. |
| `-Help`                                     | Show help and exit.                                                                  |
| `-Menu`                                     | Open the menu with supplied defaults; incompatible with `-NonInteractive`.           |

Scan filters affect wrapper validation and reporting only. Change `sisou.toml` to control downloads. Scanning reports `.iso` files; other images, such as `.img`, are not included.

SHA-256 comparison detects content changes but is not a verification against a trusted publisher checksum. ISO header validation is a format check, not an authenticity check, and can reject images without an ISO-9660 descriptor.

## Run Outcomes

| Exit code   | Meaning                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------- |
| 0           | Successful run or dry run; also used when SISOU only creates its initial config.         |
| 10          | Missing or unrecognized Ventoy drive / invalid selection.                                |
| 20          | Managed runtime setup or health check failed.                                            |
| 30          | SISOU exited unsuccessfully or logged updater errors despite exiting zero.               |
| 40          | Invalid inputs, runner config, TOML syntax, or ISO header validation failure.            |
| 50          | Reserved/documented installation failure code; current runtime setup failures return 20. |
| 60          | Another runner holds the runtime lock.                                                   |
| 99          | Unexpected wrapper error.                                                                |
| 130         | User cancellation recognized by the wrapper.                                             |

A non-zero SISOU process exit can trigger retries with exponential backoff. Upstream per-updater errors often leave the SISOU process exit code at zero; these are counted and reported as a partial failure without automatically rerunning every updater.

Use the runner's logging options rather than overriding SISOU's log file through
`-SisouArgs`. The wrapper's log tailing and updater-error count currently follow
its own generated SISOU log path.

Ctrl+C requests cancellation, stops the active Python process tree, suppresses retries, and records cancellation when the wrapper can complete its cleanup. Cancellation checks during other phases occur at the next checkpoint; a hash read already in progress may take time to finish. Force-ending the process or closing its host does not guarantee a final report.

## Reports and Privacy

The report stores filenames, sizes, timestamps, optional hashes, status changes, runtime versions, GnuPG availability, and updater error counts. Internal absolute file identities are used to distinguish identical filenames in different directories, then removed before serialization. Removed/added version pairs are matched heuristically within the same directory.

Raw forwarded arguments and stdout/stderr tails are omitted from reports. Logs retain detailed errors, paths, and tracebacks and can contain usernames or other sensitive data. Filenames and configured patterns can also contain user-chosen sensitive text.

State and report writes use atomic replacement. A failed replacement preserves the previous JSON. Reports represent the latest saved run, not a permanent history. Dry runs still write local logs, state, a report, and a runtime lock; they do not change USB images or set up Python.

See [GDPR-compliance.md](GDPR-compliance.md) for the technical privacy notes.

## Troubleshooting

- **First run downloaded nothing:** inspect the newly generated USB `sisou.toml`, select the updaters you need, and run again.
- **Runtime failed:** check the local log for interpreter, pip, or dependency errors. A venv relies on its base Python installation; removing that installation can break it.
- **GnuPG missing:** use `-InstallGpg` or install it separately. Continuing without GnuPG can skip signature verification.
- **Kali / libtorrent failure:** the managed workaround can make Kali optional and disable it in config. Other updaters can proceed. Restoring native dependencies does not automatically re-enable a previously disabled config entry.
- **Upstream mirror error:** check the SISOU log and disable the affected updater if necessary. HTTP errors, Microsoft download restrictions, and upstream parser failures cannot be fixed by reinstalling Python.
- **Exit 60:** wait for the other runner to finish. Do not delete an active lock file to bypass protection.
- **Interrupted download:** an incomplete file may remain. Restart or resume behavior depends on SISOU and the updater; the wrapper does not promise resumable downloads.

## Development Checks

Run all offline checks:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_all.ps1
pwsh -NoProfile -File .\Debug\test_all.ps1
```

The [debug guide](Debug/README.md) describes the AST-based harness and regression tests. Tests do not install packages, access the USB, or download images. Current checks cover parsing/static analysis, example configs, real ISO header validation, process output and cleanup, cancellation flags, argument quoting, report privacy, atomic-write failures, locking, and runtime health contracts.

## Project Todo List

- [x] Automatic runtime management with isolated SISOU packages
- [x] Ventoy detection, interactive menu, and command-line help
- [x] Local logs, structured reports, and atomic state writes
- [x] Scan controls, optional hashing, and ISO header validation
- [x] Cancellation, process-tree cleanup, and runtime locking
- [x] Offline regression harness and test suite
- [ ] Modularize the application beyond its test harness
- [ ] Cross-platform support
- [ ] Continue checking compatibility with new SISOU versions

## Credits

[Joshua Vandaele](https://github.com/JoshuaVandaele) for SISOU and the [Ventoy project](https://github.com/ventoy/Ventoy).
