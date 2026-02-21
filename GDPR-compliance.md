# GDPR Compliance Assessment: sisou-runner

## Overview

sisou-runner is a PowerShell wrapper for SuperISOUpdater (SISOU) that automates ISO updates on Ventoy USB drives. This assessment reviews the script's handling of personal data and its compliance with the General Data Protection Regulation (GDPR).

## Data Processing

sisou-runner does not process, store, or transmit personal data by default. The script operates on ISO files and USB drives, focusing on system administration tasks. All logs and reports are designed to avoid collecting personally identifiable information (PII).

### Data Collected

- **ISO file names** (no full paths)
- **Drive letter** (e.g., "F:")
- **File sizes, modification times, and hashes**
- **Log messages and error codes**

### Data Excluded

- No usernames
- No absolute file paths
- No user-specific environment variables
- No network addresses or device serials

## Privacy-Safe Reporting

- JSON reports intentionally omit full paths and usernames
- Logs are stored locally and not transmitted externally
- No telemetry or analytics are included

## Storage Locations

- **Logs:** `%ProgramData%\SISOU\logs` (default; can be customized)
- **Reports:** `%ProgramData%\SISOU\report.json` (default; can be customized)
- **State file:** `%ProgramData%\SISOU\state.json` (default; can be customized)

All files are stored on the local machine. Users can change the log directory using the `-LogDir` parameter when running the script.

## User Controls

- Users can review and delete logs and reports at any time
- All configuration is local; no cloud or remote storage

## Recommendations

- If integrating with external systems, ensure no PII is added to logs or reports
- If sharing logs/reports, review for accidental inclusion of sensitive data
- Keep software up to date to avoid vulnerabilities

## Conclusion

sisou-runner is designed to be GDPR-compliant by default, as it does not process or store personal data. Users are responsible for maintaining compliance if they modify the script or integrate it with other systems.

## Contact

For GDPR-related questions or concerns, contact the repository maintainer.
