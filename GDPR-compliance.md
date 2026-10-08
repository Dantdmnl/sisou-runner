# Privacy and Data Handling

Updated: 2026-10-08.

This document describes the runner's technical behavior. It does not certify GDPR compliance. The historical filename is retained for existing links.

## Local Reports

`report.json` includes ISO filenames, a drive letter, file sizes and timestamps,
optional SHA-256 hashes, statuses, scan settings, runtime versions, GnuPG
availability, and SISOU attempt/error information.

The runner removes internal absolute file identities before saving. It saves only
the SISOU log's filename, omits forwarded SISOU argument values, removes raw
stdout/stderr tails, and uses a generic cancellation reason.

These measures reduce disclosure; they do not anonymize arbitrary user input.
An ISO filename, config filename, include/exclude pattern, or renamed file can
itself contain sensitive text. Review reports before sharing them.

`state.json` stores the most recently recorded stage, a timestamp, and stage
details such as counts and outcomes. It is not a durable audit history. Reports
and state use atomic replacement to preserve the prior file on write failure.

## Diagnostic Logs

Wrapper logs and SISOU logs retain details needed for troubleshooting. They can
contain absolute paths, usernames, download URLs, addresses, errors, and Python
tracebacks. They are not subject to the report's field sanitization.

The runner writes these logs locally. It does not automatically upload logs or
reports, and it has no built-in analytics or telemetry sender. The runner does
not enforce automatic log retention or deletion.

## Network Activity

Live runs can contact Python download servers, package indexes, winget sources,
distribution mirrors, publisher sites, and signature/key services used by the
installed SISOU dependencies. These services receive ordinary request metadata,
including the connecting address. Proxy settings and downstream tools can affect
which services are contacted.

The runner's local report policy is not a statement about third-party services'
data handling. Dry-run mode skips runtime setup, package installation, and SISOU
execution, but still writes local diagnostic files.

## Storage and Controls

Host data defaults to `%ProgramData%\SISOU`, with a
`%LocalAppData%\SISOU` fallback when needed. `-LogDir` changes logs only;
there are no separate report/state path parameters.

SISOU TOML configuration and images normally reside on the selected USB drive.
An explicit TOML config can direct downloads elsewhere. The managed Python
environment remains on the host.

Users can review and remove local logs or reports after a run has finished.
Deleting the runtime also removes installed SISOU packages, so a future run will
need setup again. Review diagnostic logs and user-chosen names before posting
them publicly.
