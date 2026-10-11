# Fork CI triggers

Upstream syncs update `main` and `codex/cbm-local-fixes`. These pushes do not
need another upstream compliance scan, Pages deployment, or coverage bundle.

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

The trigger changes take effect after this branch is merged into `main`.
