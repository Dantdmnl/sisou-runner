# sisou-runner v2.3

This release improves Windows runtime isolation, process cleanup, reporting, and
interactive operation. SISOU itself remains an upstream dependency; its version is
recorded separately from the runner version.

## Highlights

- Isolated managed SISOU packages, interpreter/import validation, and pip dependency checks.
- Empty-drive initialization, absolute config paths, strict runner JSON settings, and TOML preflight.
- Concurrent child output draining, correct Windows argument quoting, and process-tree cleanup.
- Native cancellation flags, no retries after recognized cancellation, and exit code 130.
- Atomic JSON writes and an exclusive runtime lock; exit code 60 indicates another active runner.
- Accurate duplicate-filename matching and sanitized reports without raw arguments/output tails.
- Updater error counts and exit code 30 for partial failures despite an upstream zero exit.
- Menu preview by default, drive/config selection, last-report summary, and preserved defaults.
- Offline regression coverage for both Windows PowerShell 5.1 and PowerShell 7.

## Behavior Changes

Pressing Enter in the menu now previews; choose 1 for a live run. Shared system
Python packages are not modified by fallback installation. JSON switches must be
actual booleans, and numeric settings must be integers in their supported ranges.
Report output tails and internal paths are omitted; detailed diagnostics remain
in local logs.

On a drive without sisou.toml, SISOU creates a default config and returns. Review
its enabled images before running again, as many large downloads may be enabled.

## Validation and Limits

All offline tests and static analysis passed on PowerShell 5.1 and 7. Live testing
on F: created its config and downloaded five ISOs before the run was stopped at
the user's request. A Rescuezilla upstream parser error was observed.

The test suite does not establish coverage of every edge case. Physical Ctrl+C
delivery varies by terminal host; installer behavior, GPG trust, and upstream
mirror availability still require live verification. Custom SISOU log-file
overrides bypass the wrapper's generated-log monitoring. Interrupted downloads
are not guaranteed to resume.

## Assets

The ZIP includes the runner, example configs, docs, license, and offline debug
suite. The SHA-256 file verifies the ZIP bytes; it is not a publisher signature.
