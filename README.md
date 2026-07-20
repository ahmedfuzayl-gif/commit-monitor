# commit-monitor (always-on)

Fresh-commit security monitor for bug-bounty **source review**. Runs 24/7 on GitHub Actions —
laptop-independent. Scoring is **profile-aware**: each watched repo is scored with the vocabulary
that fits it — `blockchain` (node-client mem-safety / consensus), `web` (web-app injection/authz/
XSS sinks **plus new endpoint/route declarations**), or `generic` (the union, for mixed targets).

## Why this exists
The recurring killer in OSS source-review bounties is **duplicates**: stable, released code is
already audited, so real bugs you find were often found first (by other hunters or the vendor's
own team). Fresh commits are un-audited by construction — reviewing them the moment they land is
how you're *first*. This watches new commits across in-scope, **paid**, source-scoped infra repos
and surfaces only the security-relevant delta.

## How it works
- `.github/workflows/commit-monitor.yml` runs every 6h (and on-demand from the Actions tab).
- `bin/commit-monitor.py` fetches commits since the last-seen SHA per repo (`commit-monitor/
  state.json`), scores each per-commit for security relevance (consensus/p2p/crypto/tx/rpc/
  arithmetic/panics; merge commits skipped), and ranks a digest.
- **On findings it opens a GitHub Issue** (you get an email) and commits the updated state back.
- Uses the **built-in workflow token** for API reads — no personal token stored as a secret.

## Reading the output
- **🔴 SECURITY-FIX → variant-analysis**: a vendor patched a bug here. Pull the diff and hunt the
  same pattern in sibling files they *didn't* fix. n-day → 0-day. Highest value.
- **🟠 risky new code**: fresh attack surface — new panics/arithmetic/parsing in hot paths
  (`blockchain`), or a **new endpoint/controller/sink** (`web`). Note: the `web` profile flags
  feature commits that add attack surface **even with no security keyword in the subject** — a
  brand-new file under a hot path (`controller/`, `route`, `graphql`, …) scores on its own.
- Discipline: **reachability-FIRST** — before building any PoC, prove attacker-controlled input
  reaches the sink AND a real trust boundary is crossed. (Hard-won lesson: a passing PoC can
  still be demonstrating intended behavior.)

## Watchlist
`watchlist.json` — repos verified **paid + source-code in-scope** (Cosmos, Chia, Circle,
Lightspark, TRON, Chainlink). Each entry sets a **`profile`** (`blockchain` | `web` | `generic`)
that picks its scoring vocabulary; unset defaults to `blockchain`. To watch a web app (e.g. a
GitLab-class target), add it with `"profile": "web"`. Add repos as you confirm scope on new
programs; **verify a repo is still in-scope before reporting anything against it.**

## Local use (optional)
Also runnable locally: `python3 bin/commit-monitor.py [--backfill N] [--repo owner/name]
[--min-score N]`. Set `GITHUB_TOKEN` env (or a chmod-600 `commit-monitor/.env`) for 5000 req/hr.

## Maintenance
- Adjust cadence: edit the `cron:` line in the workflow (currently every 6h).
- Noise floor: the workflow runs with `--min-score 5`; lower it for more (noisier) leads.
- Pause: disable the workflow in the Actions tab.
