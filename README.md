# commit-monitor (always-on)

Fresh-commit security monitor for OSS source review. Runs on GitHub Actions without a laptop and
collects default-branch commits from both GitHub and GitLab. Scoring is profile-aware:
`blockchain`, `web`, `systems`, `desktop`, or `generic`.

## Why this exists
The recurring killer in OSS source-review bounties is **duplicates**: stable, released code is
already audited, so real bugs you find were often found first (by other hunters or the vendor's
own team). Fresh commits are un-audited by construction — reviewing them the moment they land is
how you're *first*. The watchlist now mixes confirmed paid bounties with high-value coordinated
disclosure programs; each entry labels its reward status and links the policy.

## How it works
- `.github/workflows/commit-monitor.yml` runs every 6h and supports manual dispatch.
- `bin/commit-monitor.py` fetches every commit since the per-target SHA in
  `commit-monitor/state.json`. GitHub and GitLab responses are normalized before scoring.
- A target's watermark advances only after a complete commit-and-diff pass. Missing history,
  truncated diffs, API errors, and rate limits are visible coverage failures.
- Findings and coverage failures are saved as timestamped digests and sent to a GitHub Issue.
  State still commits if issue notification fails, preventing one bad alert from replaying the
  same backlog forever.
- `GITHUB_TOKEN` uses the workflow token. Public GitLab projects need no token; an optional
  `GITLAB_TOKEN` raises GitLab limits for large backfills.

## Reading the output
- **`[SECURITY FIX]`**: explicit CVE/advisory/vulnerability language, or a patch carrying a
  concrete security signal. Highest-priority variant analysis.
- **`[PATCH]`**: an ordinary bug-fix or hardening patch. Worth sibling-path review, but not
  mislabeled as a disclosed vulnerability.
- **`[NEW SURFACE]`**: a feature commit, new sensitive file, endpoint, parser, unsafe primitive,
  desktop IPC boundary, or other risky added code.
- **`[REVIEW]`**: a lower-confidence lead that still crossed the configured score.

Reachability first: prove attacker-controlled input reaches the changed code and crosses a real
trust boundary before building a PoC.

## Watchlist
`watchlist.json` currently contains 38 active repositories across GitLab, WordPress, Kubernetes,
Brave, MetaMask, major web applications, systems software, and selected active blockchain
programs. Inactive SDK-only targets were removed.

Every entry declares:
- `provider`: `github` or `gitlab`
- `repo`: provider namespace/path; nested GitLab groups are supported
- `profile`: `blockchain`, `web`, `systems`, `desktop`, or `generic`
- `reward`: `bounty` or `vdp`
- `policy` and `policy_checked`: evidence to re-check before testing or reporting

Only explicit watchlist entries are monitored; organization-wide auto-discovery is intentionally
disabled. Monitoring is limited to each repository's default branch unless an entry sets `branch`.

## Local use
```text
python3 bin/commit-monitor.py --list-targets
python3 bin/commit-monitor.py --provider gitlab --reward bounty --list-targets
python3 bin/commit-monitor.py --repo gitlab-org/gitlab --backfill 20 --no-save
python3 bin/commit-monitor.py --min-score 4
```

Set `GITHUB_TOKEN` and optionally `GITLAB_TOKEN` in the environment or in a chmod-600
`commit-monitor/.env`. `--backfill N` ignores the watermark and scans exactly the newest `N`
commits. Pair exploratory backfills with `--no-save`. A newly added target is baselined to its
current head on the first normal run, so history is never mistaken for fresh code.

## Maintenance
- Re-check `policy` links and `reward` labels before acting on a lead.
- Adjust cadence in `.github/workflows/commit-monitor.yml` (currently every 6h).
- The workflow score floor is 3; raise `--min-score` for less volume.
- API diff size limits are reported in the digest; inspect the linked commit manually.
- Pause by disabling the workflow in the Actions tab.
