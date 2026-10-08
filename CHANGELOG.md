# Changelog

## 2.3 - 2026-10-08

Release notes for v2.3. The previous v2.2 release and its assets remain unchanged.

- Allow SISOU to initialize an empty Ventoy drive.
- Keep package installs and repairs inside the managed environment.
- Validate the managed interpreter, SISOU imports, and pip dependencies; record the SISOU version.
- Drain redirected child output concurrently to prevent pipe stalls.
- Use native cancellation flags, process-tree cleanup, and cancellation-aware retries.
- Quote Windows arguments correctly and resolve relative SISOU config paths.
- Normalize the advertised bare drive-letter shorthand before Ventoy detection.
- Accept bare drive letters in manual drive selection and tolerate cleanup of an unstarted child process.
- Distinguish duplicate ISO filenames internally and constrain update pairing to the same directory.
- Remove internal paths, raw arguments, and child output tails from JSON reports.
- Write state and reports atomically; prevent overlapping runners with an exclusive runtime lock.
- Validate runner JSON types and TOML syntax before download attempts.
- Report updater errors even when SISOU returns zero; return exit code 30 for partial failure.
- Test real ISO header validation, including its minimum descriptor boundary.
- Add an AST-based test harness and one command for the offline suite.
- Run the offline suite in GitHub Actions on Windows PowerShell 5.1 and PowerShell 7.
- Document first-run setup, storage locations, privacy limits, and exit codes.
- Use a nightly-image example exclusion rather than excluding names such as MemTest.
- Default the interactive menu to preview, with explicit Run and Debug run choices.
- Add drive/config selection, a latest-report summary, and `-Menu` with supplied defaults.
- Preserve bound defaults and drive/config selections when returning to the menu.
- Record the runner version in JSON reports.
- Fix the case-insensitive collision between the `Menu` switch and menu result variable; test the actual entry-point handoff.

## 2.2

- Advanced runner JSON defaults and ISO scan include/exclude/depth controls.
- Optional ISO-9660 header validation and faster collection lookups.
- Upstream CLI, Windows path, and TOML BOM compatibility fixes.
- Managed SISOU venv and GnuPG preflight/installation prompt.
- Dry-run, cancellation, and progress rendering improvements.
- Example configurations and initial integration checks.

## 2.1

- Windows PowerShell 5.1 support.
- Interactive launch menu and pause/back-to-menu flow.
- Real-time SISOU log tailing and traceback display.
- Improved dry-run output, help, and limitation documentation.
- Removed/added ISO version pairing and Python discovery improvements.

## 2.0

- Major wrapper overhaul with structured reports, Ventoy detection, SHA-256 hashing,
  retries, and initial cancellation handling.
