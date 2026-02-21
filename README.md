# sisou-runner

## Version

**Current Version:** 2.0

This release marks a major overhaul with improved automation, privacy, and user experience.

## Project Todo List

- [x] Major overhaul and rename
- [x] Advanced logging and privacy reporting
- [x] Automatic Python runtime management
- [x] Robust Ventoy detection
- [x] SHA-256 hashing for ISOs
- [x] Improved documentation and GDPR compliance
- [x] Version tracking in script and logs
- [ ] User-friendly error messages
- [ ] Expand advanced config options
- [ ] Integration tests and example configs
- [ ] Optimize for large ISO collections
- [ ] Refactor for modularity
- [ ] Support additional ISO validation
- [ ] Improve dry-run output
- [ ] Command-line help for all parameters
- [ ] Cross-platform support
- [ ] Ensure compatibility with SISOU upstream
- [ ] Document SISOU limitations

## Overview

sisou-runner is a robust PowerShell wrapper for SuperISOUpdater (SISOU), automating ISO updates on Ventoy USB drives. It manages Python runtime setup, Ventoy drive detection, ISO integrity checks, retry logic, and privacy-safe reporting.

## Prerequisites

- **Windows** with PowerShell 5.1 or later
- **Ventoy** installed on your USB drive ([Ventoy project](https://github.com/ventoy/Ventoy))
- **Internet access** for Python/SISOU installation (unless using offline options)
- **PowerShell Execution Policy**: The script requires the execution policy to be set to `RemoteSigned` or less restrictive. To set this, run:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Features

- Automatic Python 3.12+ runtime detection and installation (system, managed, or via winget)
- Installs and upgrades SuperISOUpdater (SISOU) as needed
- Reliable Ventoy USB drive detection (multiple strategies)
- Optional SHA-256 hashing for ISOs
- Structured logging and privacy-safe JSON reporting
- Handles Ctrl+C gracefully, cleans up child processes
- Supports dry-run mode, retry logic, and custom SISOU arguments
- Advanced error handling and reporting

## Usage

Run the script in PowerShell:

```powershell
pwsh -File sisou-runner.ps1
```

### Common Options

- `-Drive <letter>`: Specify Ventoy drive letter (auto-detected if omitted)
- `-ConfigFile <path>`: Path to SISOU config.toml
- `-LogLevel <level>`: SISOU log verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `-LogDir <path>`: Directory for logs (default: %ProgramData%\SISOU\logs)
- `-RetryCount <n>`: Number of retry attempts on failure (default: 2)
- `-TimeoutSeconds <n>`: Timeout per SISOU run (default: 3600)
- `-HashThrottle <n>`: Parallel SHA-256 threads (default: 4)
- `-VerifyHashes`: Compute SHA-256 for ISOs before/after
- `-SkipPipUpgrade`: Skip SISOU upgrade step
- `-DryRun`: Preview actions without running SISOU
- `-NonInteractive`: No prompts; fail fast if input is missing
- `-UseWinget`: Force winget/system Python
- `-Help`: Print usage and exit
- `-- <args>`: Extra arguments forwarded to SISOU

#### Example: Full Automated Run

```powershell
pwsh -File sisou-runner.ps1 -LogLevel INFO -RetryCount 3 -VerifyHashes -- --my-sisou-flag
```

#### Example: Dry Run

```powershell
pwsh -File sisou-runner.ps1 -DryRun
```

#### Example: Custom Config

```powershell
pwsh -File sisou-runner.ps1 -ConfigFile "C:\path\to\config.toml"
```

See `sisou-runner.ps1` for full parameter list and examples.

## Logging & Reports

- Logs are written to `%ProgramData%\SISOU\logs` (or custom directory)
- JSON reports are privacy-safe (no full paths or usernames)

## Troubleshooting

- **Execution Policy Error**: If you see a policy error, set the execution policy as described above.
- **Python Not Found**: The script will attempt to install Python automatically. If this fails, ensure you have internet access or install Python 3.12+ manually.
- **Ventoy Not Detected**: Make sure your USB drive is plugged in and Ventoy is properly installed.
- **Permission Issues**: Run PowerShell as Administrator if you encounter access errors.

## Credits

- [Joshua Vandaële](https://github.com/JoshuaVandaele) for [SuperISOUpdater](https://github.com/JoshuaVandaele/SuperISOUpdater)
- [Ventoy project](https://github.com/ventoy/Ventoy)

## License

See repository for license details.
