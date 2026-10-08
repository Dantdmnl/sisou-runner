# Offline Debug Checks

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_all.ps1
pwsh -NoProfile -File .\Debug\test_all.ps1
```

The suite stops on the first failed test. Each test runs in a separate process
using the same PowerShell executable as the suite. Windows PowerShell 5.1 and
PowerShell 7 are supported; runtime tests also use the Windows PowerShell
executable as a harmless child process fixture.

## Coverage

| File | Checks |
|------|--------|
| `test_syntax.ps1` | Parsing, function names/calls, encoding, and optional PSScriptAnalyzer checks. |
| `test_integration.ps1` | Example config contracts, parameter presence, and actual ISO header validation. |
| `test_runtime.ps1` | Large stdout/stderr streams, timeout cleanup, cancellation flag handling, quoting, duplicate file identities, and report privacy. |
| `test_state.ps1` | Atomic JSON writes, failed replacement preservation, temp-file cleanup, lock release/exclusion, and config type/range validation. |
| `test_health.ps1` | SISOU version metadata and rejection of broken dependency requirements using mocked Python results. |
| `test_inputs.ps1` | Drive shorthand normalization with mocked drive access. |
| `test_menu.ps1` | Preview default, explicit run/debug choices, drive/config selection, returning from views, and cancellation using simulated answers. |
| `test_timeout.ps1` | Unlimited duration, explicit total-run limits, and the production retry guard. |

PSScriptAnalyzer is used when already installed. The suite does not install it;
the syntax check reports its absence as skipped. A passing suite with that check
skipped is not equivalent to a completed analyzer run.

## Harness and Fixtures

`SisouTestHarness.ps1` parses the application and imports named function bodies
through the PowerShell AST. It does not run the menu, drive selection, Python
bootstrap, package installation, or application entry point. Stateful tests can
replace external operations with controlled results.

Runtime/state tests use unique temporary fixture names and remove them afterward.
State/report fixtures are placed under `Debug` so atomic file operations work
inside a workspace sandbox. Integration ISO fixtures use the host temp directory.

The suite neither accesses the USB drive nor downloads images. Cancellation tests
exercise the native cancellation flag and process cleanup, not physical Ctrl+C
delivery in every terminal host. Actual mirrors, GPG trust, full downloads, and
installer behavior require separate live verification.

## Adding a Regression

Import the production function rather than copying its algorithm into a test.
Use an isolated fixture or mock for external dependencies. Check both the expected
result and a failure path when the change affects persistent state or processes.
Register the new test in `test_all.ps1` and keep it offline.
