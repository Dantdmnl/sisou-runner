# Revival Plan for Automated-SuperISOUpdater

This project can be relaunched as a reliable wrapper around `SuperISOUpdater` with clear goals, modern packaging, and safer Windows automation.

## 1) Product Direction

### Primary goal
Provide a simple, dependable command for Windows users to:
- Ensure Python is installed.
- Install/update `sisou` (SuperISOUpdater).
- Detect a Ventoy drive (or allow manual selection).
- Run ISO updates with clear progress and errors.

### Non-goals (for v1)
- Re-implementing SuperISOUpdater logic.
- Cross-platform feature parity (focus on Windows first).
- Complex GUI (CLI first; GUI later if needed).

## 2) Technical Refresh Strategy

### Phase A — Stabilize current PowerShell script (quick win)
1. Add strict mode and robust error handling (`Set-StrictMode`, `$ErrorActionPreference = 'Stop'`).
2. Replace deprecated `Get-WmiObject` with `Get-CimInstance`.
3. Validate user-entered drive letters and confirm path existence.
4. Improve dependency checks (`python`, `pip`, `sisou`) and report versions.
5. Add explicit exit codes and actionable error messages.

### Phase B — Project hygiene
1. Add repository structure:
   - `scripts/` for PowerShell entrypoints.
   - `docs/` for usage + troubleshooting.
   - `tests/` for Pester tests.
2. Add CI (GitHub Actions) to run lint + tests for PowerShell.
3. Add release workflow for versioned script artifacts.
4. Add changelog and semantic versioning.

### Phase C — UX improvements
1. Add `-WhatIf`/dry-run mode.
2. Add `-DriveLetter` parameter + interactive fallback.
3. Add logging to file (`logs/`) and concise console output.
4. Add support for configurable sisou options.

### Phase D — Optional modern wrapper
If long-term maintenance grows, migrate to a small Python CLI wrapper that:
- Uses `argparse` or `typer`.
- Delegates update logic to `sisou`.
- Keeps a tiny PowerShell bootstrapper for Windows convenience.

## 3) Suggested Milestones

## Milestone 1 (1–2 days)
- Harden existing script (strict mode, error handling, CIM migration).
- Improve README with setup, examples, and troubleshooting.
- Tag `v0.2.0`.

## Milestone 2 (2–4 days)
- Add tests and CI.
- Add logging + parameterized execution.
- Tag `v0.3.0`.

## Milestone 3 (1 week)
- Add optional Python wrapper or richer PowerShell module layout.
- Prepare first "production-ready" release.
- Tag `v1.0.0`.

## 4) Backlog (prioritized)

1. **Reliability**: make all network/download operations retry-safe.
2. **Observability**: structured logs and clear terminal summaries.
3. **Maintainability**: refactor script into reusable functions with unit tests.
4. **Security**: verify installer/download integrity where possible.
5. **Documentation**: include common failure scenarios (execution policy, missing admin rights, Ventoy detection issues).

## 5) Immediate Next Actions

1. Move `update-isos.ps1` into `scripts/update-isos.ps1`.
2. Implement strict mode + improved error handling.
3. Add command parameters (`-DriveLetter`, `-NonInteractive`, `-VerboseLogging`).
4. Add a `docs/TROUBLESHOOTING.md` with common fixes.
5. Add a CI workflow for PowerShell lint + tests.

---

If you want, the next step can be a concrete **Milestone 1 implementation PR** that hardens the current script without changing end-user behavior.
