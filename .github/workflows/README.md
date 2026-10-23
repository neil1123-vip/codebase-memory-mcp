# Fork CI triggers

`main` mirrors upstream `main` exactly. Local fixes and fork CI configuration
live on `codex/cbm-local-fixes`, where upstream changes are merged.

Scheduled sync requires `codex/cbm-local-fixes` to be the repository's default
branch, since upstream `main` does not contain `sync-upstream.yml`. The main
sync job mirrors the fetched upstream commit with an explicit lease; it fails
if another writer updates `main` after checkout.

The following trigger policy applies to `codex/cbm-local-fixes`. The workflows
on `main` remain identical to upstream.

| Trigger | Workflows |
| --- | --- |
| Every 6 hours, or manual | Sync upstream main |
| Pull requests to `main` | PR, CodeQL SAST |
| Pull requests | DCO |
| Newly opened pull requests | PR acknowledgement |
| Manual only | OpenSSF Scorecard, Deploy Pages, Cache warm, Nightly Soak, Stale awaiting-reporter, test-impact-artifact |
| Manual or explicit `qa/fast-**` / `qa/smoke-**` pushes | Fast Repro / Smoke (all platforms) |
| Manual only | Dry Run, Release, Bug Repro Board |

PR lint, tests, smoke and security gates retain their existing lane selection.
Test-impact artifacts can be refreshed manually from `main`. Without a bundle,
selection runs complete affected suites rather than narrowing individual tests.

Before dispatching Dry Run or Release, run CodeQL SAST on the same branch and
commit. The security gate fails immediately if that scan has not been started,
and still requires a successful scan and no open alerts.
