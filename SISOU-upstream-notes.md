# SISOU Upstream Notes

Research date: 2026-06-05

Local runner/source audit: 2026-10-08. Version observations below are historical
research results, not a claim about the latest GitHub or PyPI release today.

## What SISOU Is

Super ISO Updater (SISOU) is Joshua Vandaele's Python CLI for updating ISO files, primarily on a Ventoy drive. It reads a `sisou.toml` configuration, checks supported ISO families against upstream sources, downloads newer versions, and verifies downloads with checksums and, where available, signatures.

Upstream sources:

- GitHub: https://github.com/JoshuaVandaele/SuperISOUpdater
- PyPI: https://pypi.org/project/sisou/

## Upstream Shape Observed in June 2026

- PyPI latest observed: `sisou 2.2.0`, released 2026-05-12.
- GitHub `main` observed version: `2.3.0`.
- Upstream README prerequisite: Python 3.12+.
- Upstream README lists GnuPG as optional for signature verification. In practice, missing `gpg.exe` causes repeated `python-gnupg` tracebacks and skipped signature checks for signed downloads.
- Package metadata says `>=3.10, <4`, but current source uses Python 3.12 f-string grammar, so Python 3.11 fails with `SyntaxError: f-string expression part cannot include a backslash`.
- SISOU's CLI takes one positional `config_path`, which can be either a directory containing `sisou.toml` or the config file itself.
- SISOU logging flags are `-l/--log-level` and `-f/--log-file`; there is no current `-c/--config-file` flag.

## Dependency Caveat

SISOU imports all updater classes at startup through `modules.updaters.__init__`. The Kali updater imports `torrentp`, which imports the native `libtorrent` Python binding. This means SISOU can fail before doing any config parsing, even when the user is not intending to update Kali.

Observed failure:

```text
ImportError: DLL load failed while importing libtorrent: The specified module could not be found.
```

`libtorrent 2.0.11` has Windows CPython 3.12 wheels on PyPI, so this is likely a broken native dependency install or missing DLL dependency rather than a complete lack of Windows wheels.

On Windows, compiled `.pyd` extensions can fail with the generic "specified module could not be found" message when one of their dependent DLLs is missing. A common cause is a missing or damaged Microsoft Visual C++ Redistributable. The wrapper now avoids shared Python-package conflicts by preferring a clean managed venv first, but an OS-level native DLL problem can still require repairing the Visual C++ 2015-2022 Redistributable x64 package.

## Wrapper Implications

- Treat Python 3.12 as the minimum runtime for current SISOU.
- Do not treat `py.exe` as a separate candidate when concrete `python.exe` paths are available.
- Pass `ConfigFile` as SISOU's positional `config_path`, not with `-c`.
- If SISOU import fails on `libtorrent`, try a targeted reinstall of `libtorrent` and `torrentp` once before failing.
- Prefer an isolated SISOU venv created from an installed Python 3.12+ over the user's shared system Python.
- Do not loop through winget when Python 3.12+ is already present but native DLL loading is the remaining failure.
- In the managed venv only, if `libtorrent` still cannot load after repair, patch SISOU's updater registry so `KaliLinux` becomes optional and disable Kali in SISOU config/default config. This is a workaround for SISOU's eager import behavior and lets non-Kali ISO updates proceed.
- Keep dry-run mode free of Python, pip, winget, and managed runtime side effects.
- Check for GnuPG before live runs, offer winget installation interactively, and ensure SISOU inherits a PATH containing the discovered `gpg.exe` directory.

## Local Source Audit in October 2026

Inspection of the installed SISOU entry point confirmed that a missing config is
copied from its bundled template and the process returns without running updaters.
The wrapper therefore permits empty ISO collections so this initialization works.

The entry point catches exceptions while creating and running individual updaters,
logs them, and continues. A zero process exit alone does not prove every updater
succeeded. The wrapper counts ERROR entries in the SISOU log and reports a partial
failure with exit code 30; it does not automatically rerun all updaters in that case.

SISOU changes its working directory to the config's parent. The runner passes
absolute config paths to avoid relative-path failures, and validates TOML syntax
before launching download attempts. Directory values in an explicit config can
still direct downloads outside the selected USB drive.
