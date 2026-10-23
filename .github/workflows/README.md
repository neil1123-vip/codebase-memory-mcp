# Fork CI triggers

`main` keeps upstream business code and workflows, with only
`sync-upstream.yml` added for this fork. Local fixes and other fork CI
configuration live on `codex/cbm-local-fixes`.

`main` remains the repository's default branch so its sync workflow runs every
6 hours. Its sync job rebases the fork's sync workflow commits onto upstream,
then pushes with an explicit lease against the checked-out `main` commit.
The local-fixes job also rebases its patches onto upstream and pushes with an
explicit lease against its checked-out commit. Both jobs fail on rebase
conflicts or concurrent branch updates, without adding sync merge commits.

The following trigger policy applies to `codex/cbm-local-fixes`. The workflows
on `main` follow upstream policy, with the added scheduled sync.

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
