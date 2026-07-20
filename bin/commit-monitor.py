#!/usr/bin/env python3
"""
commit-monitor: the source-code sibling of monitor.sh.

Philosophy (same as this workspace): be FIRST to new attack surface. For source
review that means reviewing NEW COMMITS the moment they land -- before the
vendor's own security team and other hunters get to them. Stable, released code
is already audited and duplicate-prone; the fresh delta is where an
undiscovered, un-raced bug lives.

What it does:
  * Watches the in-scope repos in watchlist.json (per bounty program).
  * On each run, fetches commits since the last-seen SHA (append-only state,
    like monitor.sh's diffnew), and surfaces ONLY the new ones.
  * Scores each commit for security relevance, tuned for BLOCKCHAIN INFRA /
    node clients (consensus, p2p, crypto, tx/mempool, rpc, arithmetic, panics).
  * Flags likely SECURITY-FIX commits as top priority -- these are
    variant-analysis gold: when a vendor patches bug X here, the same pattern
    often survives un-fixed in a sibling file. n-day -> 0-day.
  * Emits a ranked markdown digest; you review only the delta, then go hunt.

Usage:
  commit-monitor.py                 # check all repos, surface new commits
  commit-monitor.py --backfill 40   # first-run demo: score last N commits/repo
  commit-monitor.py --repo cosmos/gaia --backfill 40   # one repo
  commit-monitor.py --min-score 4   # only show commits at/above a score

Auth: set GITHUB_TOKEN in the env for 5000 req/hr (vs 60 unauth). ~2 calls/repo.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ~/bounty
WATCHLIST = os.path.join(BASE, "watchlist.json")
STATE_DIR = os.path.join(BASE, "commit-monitor")
STATE = os.path.join(STATE_DIR, "state.json")
DIGEST_DIR = os.path.join(STATE_DIR, "digests")
API = "https://api.github.com"


def _load_env():
    # Auto-load GITHUB_TOKEN (etc.) from a gitignored, chmod-600 .env so the
    # token never needs to appear on a command line or in the crontab.
    for p in (os.path.join(STATE_DIR, ".env"), os.path.join(BASE, ".env")):
        try:
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        v = v.strip()
                        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                            v = v[1:-1]  # strip matching surrounding quotes
                        os.environ.setdefault(k.strip(), v)
        except FileNotFoundError:
            pass


_load_env()

# ---- scoring, tuned for blockchain-infra / node-client bugs ----------------
# Message words that flag a likely SECURITY FIX (highest value: variant-analysis
# candidates). Weight 3 each.
FIX_WORDS = [
    "security", "vuln", "cve", "advisory", "exploit", "attack",
    "panic", "overflow", "underflow", "oob", "out-of-bounds", "out of bounds",
    "dos", "denial of service", "crash", "hang", "deadlock", "unsound",
    "unbounded", "exhaust", "oom", "memory leak",
    "malformed", "invalid", "reject", "sanitiz", "validat", "bounds check",
    "unchecked", "double-spend", "double spend", "replay", "nonce reuse",
    "consensus", "fork", "non-deterministic", "nondeterministic", "slashing",
    "signature", "forge", "bypass", "underpriced", "griefing",
    "authoriz", "authentic", "unauthoriz", "authz", "spoof", "tamper",
    "leak", "disclos", "traversal", "injection", "ssrf", "rce", "poison",
    # web app-sec fix vocabulary (used by the "web"/"generic" profiles)
    "xss", "csrf", "idor", "sqli", "ssti", "xxe", "prototype pollution",
    "open redirect", "privilege", "escalat", "smuggl", "path traversal",
    "mass assignment", "insecure", "sandbox",
]
# Weaker generic "fix" signal. Weight 1.
SOFT_FIX = ["fix", "bug", "incorrect", "wrong", "mishandl", "edge case", "regression"]

# High-confidence security terms — unambiguous enough to scan the commit BODY,
# not just the subject. The softer domain nouns in FIX_WORDS ("validat" ->
# "validator", "signature", "consensus", "fork", "reject", "invalid") over-fire
# in long bodies, so they are deliberately EXCLUDED here to keep the 🔴 tier
# precise while still recovering fixes described in the body under a terse subject.
STRONG_FIX_WORDS = [
    "security", "vuln", "cve", "advisory", "exploit", "attacker", "malicious",
    "overflow", "underflow", "oob", "out-of-bounds", "out of bounds",
    "panic", "crash", "unsound", "dos", "denial of service",
    "bypass", "traversal", "injection", "ssrf", "rce", "xss", "csrf", "idor",
    "ssti", "xxe", "deserial", "spoof", "forge", "poison", "smuggl",
    "double-spend", "double spend", "replay", "unauthoriz", "privilege escalat",
]

# ---- per-target profiles ---------------------------------------------------
# A watchlist entry selects one via "profile": "blockchain" | "web" | "generic".
#   * paths  -> security-relevant path fragments (CONTEXT signal, weight 2 capped)
#   * flags  -> red-flag substrings on ADDED lines (fresh attack surface)
# "blockchain" is the historical default (node-client mem-safety / consensus).
# "web" swaps in injection/authz/XSS sinks AND new-endpoint/route declarations,
# so a feature commit that adds attack surface surfaces even with NO security
# keyword in the subject -- the GitLab / web-app case. "generic" is the union,
# for mixed or unclassified targets.
_BLOCKCHAIN_PATHS = [
    "consensus", "crypto", "/sig", "signature", "/key", "p2p", "/net",
    "rpc", "/api", "mempool", "txpool", "/tx", "/vm", "evm", "/state",
    "validator", "stake", "slash", "/gov", "/bank", "ibc", "bridge",
    "serde", "codec", "decode", "deserial", "rlp", "ssz", "borsh", "proto",
    "verify", "/auth", "gas", "fee",
]
_BLOCKCHAIN_FLAGS = [
    ".unwrap(", ".expect(", "panic!(", "unreachable!(", "unsafe ",
    "unchecked", "get_unchecked", "transmute", "from_raw", "as usize",
    "as u64", "as u32", "as i64", "memcpy", "while true", "loop {",
    "saturating_", "wrapping_", "overflowing_",
    "recover(", "ecrecover", "assert(", "require(",
]
_WEB_PATHS = [
    "controller", "/api", "route", "handler", "graphql", "resolver",
    "/auth", "session", "/admin", "middleware", "policy", "policies",
    "serializer", "webhook", "upload", "download", "template", "render",
    "redirect", "oauth", "saml", "/sso", "jwt", "password", "login",
    "account", "permission", "/acl", "csrf", "cors", "import", "export",
    "proxy", "/url", "/file", "settings", "/models", "/views", "query",
]
_WEB_FLAGS = [
    # command / code execution
    "system(", "exec(", "eval(", "popen(", "subprocess", "child_process",
    "os.system", "shell_exec", "proc_open", "Runtime.getRuntime",
    "ProcessBuilder", "new Function(", "spawn(", "execSync(",
    # sql
    ".raw(", "find_by_sql", "createQueryBuilder", "sequelize.query",
    "executeQuery(", "rawQuery(", "String.format", 'f"SELECT', 'f"select',
    # deserialization
    "pickle.loads", "yaml.load", "Marshal.load", "unserialize(",
    "readObject", "ObjectInputStream",
    # xss / html injection
    "html_safe", "dangerouslySetInnerHTML", ".innerHTML", "v-html",
    "mark_safe", "bypassSecurityTrust", "Markup(", "|safe",
    # ssrf / file access
    "send_file", "sendFile", "path.join(", "File.read", "readFileSync(",
    "requests.get(", "urllib.request", "fetch(", "curl_exec",
    # auth / authz weakening
    "skip_before_action", "permit!", "verify=false", "verify: false",
    "InsecureSkipVerify", "jwt.decode", "params.require",
    # NEW route / endpoint surface (feature commits = new attack surface)
    "resources :", "namespace :", "@app.route", "@router.", "Route::",
    "@GetMapping", "@PostMapping", "@RequestMapping", "app.get(", "app.post(",
    "router.get(", "router.post(", "addRoute", ".route(",
]

PROFILES = {
    "blockchain": {"paths": _BLOCKCHAIN_PATHS, "flags": _BLOCKCHAIN_FLAGS},
    "web": {"paths": _WEB_PATHS, "flags": _WEB_FLAGS},
    "generic": {
        "paths": sorted(set(_BLOCKCHAIN_PATHS) | set(_WEB_PATHS)),
        "flags": sorted(set(_BLOCKCHAIN_FLAGS) | set(_WEB_FLAGS)),
    },
}
DEFAULT_PROFILE = "blockchain"

# Noise signals: commits that are almost never a security fix / new attack
# surface. A subject starting with one of these prefixes, or containing one of
# these words, gets a strong down-weight so cleanup/docs/dep churn stops
# out-ranking real fixes.
NEG_PREFIXES = (
    "chore:", "chore(", "docs:", "docs(", "doc:", "test:", "test(", "tests:",
    "ci:", "ci(", "build:", "build(", "style:", "perf:", "refactor:", "refactor(",
    "bump ", "release", "changelog",
)
NEG_WORDS = [
    "typo", "rename", "cleanup", "clean up", "readme", "changelog", "comment",
    "formatting", "gofmt", "rustfmt", "lint", "dependabot", "version bump",
    "remove impossible", "remove unused", "dead code", "whitespace", "spelling",
    "bump version", "update deps", "upgrade dependency", "regenerate", "snapshot",
]


def _wordmatch(words, text):
    """Left-boundary PREFIX match: the term must start a word, but may have a
    suffix -- so 'vuln' matches 'vulnerability' and 'authoriz' matches
    'authorization', while 'auth' no longer sneaks in via commit-metadata words
    like 'author'/'authoritative' (we use the unambiguous 'authoriz'/'authentic'
    stems instead). Multi-word / hyphenated phrases fall back to substring."""
    hits = set()
    for w in words:
        if " " in w or "-" in w:
            if w in text:
                hits.add(w)
        elif re.search(r"(?<![a-z0-9])" + re.escape(w), text):
            hits.add(w)
    return sorted(hits)


def gh_get(path, _tries=3):
    url = path if path.startswith("http") else API + path
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    last = None
    for attempt in range(_tries):
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "commit-monitor",
        })
        if tok:
            req.add_header("Authorization", f"Bearer {tok}")
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                return json.load(r), None
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="ignore").lower()
            rem = e.headers.get("X-RateLimit-Remaining")
            # primary limit: 403 + remaining==0; secondary/abuse limit: 429, or
            # 403 whose body says rate/abuse. Signal RATE_LIMIT so callers HOLD
            # their watermark and retry next run instead of burying commits.
            if (e.code in (403, 429) and
                    (rem == "0" or "rate limit" in body or "abuse" in body
                     or "secondary rate" in body)):
                return None, "RATE_LIMIT"
            return None, f"HTTP {e.code}"
        except Exception as e:
            # transient (IncompleteRead, timeout, reset): back off and retry
            last = str(e)
            time.sleep(1.5 * (attempt + 1))
    return None, last


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, ValueError):
        # A half-written / corrupt state file must NOT crash the run or silently
        # re-baseline every repo. Preserve it for inspection and warn loudly.
        try:
            os.replace(path, path + ".corrupt")
            print(f"!! corrupt {os.path.basename(path)} -> .corrupt; using default",
                  file=sys.stderr)
        except OSError:
            pass
        return default


def save_json(path, obj):
    # Atomic write: dump to a temp file, fsync, then os.replace() (atomic on
    # POSIX+Windows). A crash/full-disk mid-write can no longer truncate the
    # crown-jewel state file to a half-written, unparseable blob.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def score_commit(message, files, profile=None):
    """Return (score, reasons[], is_secfix). files = list of {filename, patch?, status?}.
    `profile` selects the paths/flags vocabulary (see PROFILES).

    Signal weighting (v2):
      * A real FIX_WORD in the subject = a patched security bug -> variant-analysis
        gold (hunt the un-fixed siblings). Highest weight; flags is_secfix.
      * Risky NEW code (profile flags on added lines) = fresh attack surface. Boosted,
        since a new .unwrap()/panic! (blockchain) or new endpoint/sink (web) is the
        most direct "review this now" signal.
      * A NEW FILE added under a hot path (web/generic profiles) = brand-new attack
        surface even with no keyword -- catches feature commits, the GitLab case.
      * Hot paths are CONTEXT, not a standalone driver: they only add points when there
        is already a fix or risky-code signal (so a pure cleanup touching a
        consensus/proto file no longer scores high on filename matches alone).
      * Small, focused fixes get a bonus (a targeted security patch, not a big refactor).
      * Cleanup/docs/test/dep-bump churn gets a strong penalty.
    """
    prof_name = profile if profile in PROFILES else DEFAULT_PROFILE
    hot_paths = PROFILES[prof_name]["paths"]
    code_flags = PROFILES[prof_name]["flags"]

    reasons = []
    score = 0
    full = message.lower()
    subj = full.split("\n", 1)[0][:200]
    body = full[len(subj):][:2000]  # first ~2k of the body, bounded

    is_noise = subj.startswith(NEG_PREFIXES) or any(w in subj for w in NEG_WORDS)

    fix_hits = _wordmatch(FIX_WORDS, subj)
    soft_hits = _wordmatch(SOFT_FIX, subj)
    # The security signal often lives in the BODY under a terse subject
    # ("Fixes CVE-...", "prevents a panic when..."). Scan it with the
    # high-confidence subset only, and lift explicit CVE IDs as a strong signal.
    body_fix = [w for w in _wordmatch(STRONG_FIX_WORDS, body) if w not in fix_hits]
    cves = sorted(set(re.findall(r"cve-\d{4}-\d{4,7}", full)))

    def _is_noise_file(fn):
        fn = fn.lower()
        return bool(re.search(
            r"(_test\.|\.test\.|\.spec\.|/tests?/|tests?\.rs$|/mocks?/|/fixtures?/|/testdata/"
            r"|\.pb\.go$|_pb2\.py$|\.generated\.|/vendor/|/node_modules/"
            r"|\.md$|\.txt$|\.lock$|\.snap$|/docs?/"
            # generated FFI / wasm / SDK-binding artifacts (not hand-written surface)
            r"|/wasm/|wasm-browser|wasm-nodejs|_bg\.wasm|\.wasm$|\.d\.ts$"
            r"|uniffi|ffi\.|\.udl$|xcframework|/jnilibs/|\.framework/"
            r"|_generated\.|/generated/|\.min\.js$)", fn))

    code_hits, loc_added = set(), 0
    new_surface_files = []
    for f in files:
        fn = f.get("filename", "")
        if _is_noise_file(fn):
            continue  # tests/generated/docs are not new attack surface
        low = fn.lower()
        if f.get("status") == "added" and any(p in low for p in hot_paths):
            new_surface_files.append(fn)  # brand-new file in a sensitive area
        for line in (f.get("patch", "") or "").split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                loc_added += 1
                for flag in code_flags:
                    if flag in line:
                        code_hits.add(flag)
    path_hits = sorted({p.strip("/") for f in files
                        if not _is_noise_file(f.get("filename", ""))
                        for p in hot_paths if p in f.get("filename", "").lower()})

    is_secfix = bool(fix_hits) or bool(cves) or bool(body_fix)

    if fix_hits:
        score += 4 + min(len(fix_hits), 2)   # 5-6: real fix-word in subject
        reasons.append("FIX-signal: " + ", ".join(fix_hits[:5]))
    elif body_fix:
        score += 3 + min(len(body_fix), 2)   # 4-5: strong term in body, not subject
        reasons.append("FIX-signal (body): " + ", ".join(body_fix[:5]))
    elif soft_hits:
        score += 1
        reasons.append("generic-fix: " + ", ".join(soft_hits[:3]))

    if cves:
        score += 3                            # explicit CVE reference: strong standalone
        reasons.append("CVE referenced: " + ", ".join(cves[:4]))

    if code_hits:
        score += min(2 * len(code_hits), 6)   # boosted: risky new code
        reasons.append("risky-code: " + ", ".join(sorted(code_hits)[:6]))

    if new_surface_files and prof_name in ("web", "generic"):
        score += 2 + min(len(new_surface_files), 2)   # 3-4: new endpoint/handler file
        reasons.append("NEW attack surface (added file in hot path): "
                       + ", ".join(os.path.basename(p) for p in new_surface_files[:3]))

    if path_hits and (fix_hits or code_hits or new_surface_files):
        score += min(len(path_hits), 3)        # context bonus, only with a signal
        reasons.append("hot-paths: " + ", ".join(path_hits[:6]))
    elif path_hits:
        reasons.append("(touches " + ", ".join(path_hits[:4]) + " but no fix/risky-code signal)")

    if (fix_hits or body_fix) and 0 < loc_added <= 40 and len(files) <= 4:
        score += 2                              # small, focused fix = sharp variant target
        reasons.append("small focused fix -> variant-analysis target")

    if is_noise:
        score = max(0, score - 4)
        reasons.append("down-weighted: cleanup/docs/test/dep noise")

    return score, reasons, is_secfix


def gh_commits_since(repo, last_sha, backfill, cap_pages=10):
    """Walk /commits newest->oldest, PAGING until we reach last_sha (exclusive),
    collect `backfill` commits when baselining, or run out of history.

    Returns (new, head, status):
      * status None       -> clean: the watermark boundary (or end of history,
                             or the backfill count) was reached.
      * status "INCOMPLETE"-> hit the page cap with the watermark still not found,
                             i.e. more than cap_pages*100 commits landed since the
                             last run. The older tail is UNSEEN -> caller must HOLD
                             the watermark and surface it (don't silently bury it).
      * any other string  -> hard error from gh_get ("RATE_LIMIT" / "HTTP ...").
    """
    new, head = [], None
    baseline = last_sha is None
    max_pages = 1 if (baseline and backfill) else cap_pages
    for page in range(1, max_pages + 1):
        batch, err = gh_get(f"/repos/{repo}/commits?per_page=100&page={page}")
        if err:
            return new, head, err
        if not batch:
            return new, head, None                 # ran off the end of history: clean
        if head is None:
            head = batch[0]["sha"]
        for c in batch:
            if not baseline and c["sha"] == last_sha:
                return new, head, None             # boundary reached: clean
            new.append(c)
            if baseline and backfill and len(new) >= backfill:
                return new, head, None
    return new, head, "INCOMPLETE"


def process_repo(entry, state, backfill, min_score):
    repo = entry["repo"]
    prog = entry.get("program", "?")
    st = state.setdefault(repo, {})
    last = st.get("last_sha")

    # First sight with no --backfill: baseline to HEAD, don't score history.
    if last is None and not backfill:
        commits, err = gh_get(f"/repos/{repo}/commits?per_page=1")
        if err:
            return [], err
        if not commits:
            return [], "no commits"
        st["last_sha"] = commits[0]["sha"]
        st["default_branch_head_seen"] = datetime.now(timezone.utc).isoformat()
        return [], "BASELINED (run again after new commits, or use --backfill)"

    new, head, status = gh_commits_since(repo, last, backfill)
    if status and status != "INCOMPLETE":
        return [], status                          # RATE_LIMIT / HTTP: HOLD watermark
    if head is None:
        return [], "no commits"
    if not new:
        st["last_sha"] = head
        return [], "no new commits"

    # Score PER-COMMIT (accurate) rather than on an aggregate diff. Merge
    # commits (2+ parents) carry no changes of their own -- the real diff is in
    # their child commits -- so skip them as noise. One detail call per
    # non-merge commit; in normal operation there are only a handful of new
    # commits per run. (--backfill N is the expensive outlier: up to N calls.)
    #
    # CRITICAL: the watermark advances ONLY on a fully-clean pass. If a page was
    # missing (INCOMPLETE) or any per-commit detail fetch fails, we HOLD last_sha
    # and re-scan next run (a harmless duplicate in the digest) rather than
    # advance past a commit we never actually scored -- recall is the mission.
    findings = []
    n_merges = 0
    incomplete = (status == "INCOMPLETE")
    for c in new:
        if len(c.get("parents", [])) > 1:
            n_merges += 1
            continue
        msg = c["commit"]["message"]
        detail, derr = gh_get(f"/repos/{repo}/commits/{c['sha']}")
        if derr == "RATE_LIMIT":
            return findings, "RATE_LIMIT"          # bail; last_sha NOT advanced
        if derr:
            incomplete = True                      # transient/HTTP: degrade + retry
            files = []
        else:
            files = detail.get("files", [])
        score, reasons, is_fix = score_commit(msg, files, entry.get("profile"))
        if score >= min_score:
            findings.append({
                "repo": repo, "program": prog,
                "profile": entry.get("profile") or DEFAULT_PROFILE,
                "sha": c["sha"][:10],
                "url": f"https://github.com/{repo}/commit/{c['sha']}",
                "date": c["commit"]["author"]["date"],
                "author": c["commit"]["author"]["name"],
                "subject": msg.split("\n")[0][:120],
                "score": score, "reasons": reasons, "is_fix": is_fix,
            })
        time.sleep(0.15)

    scored = len(new) - n_merges
    if incomplete:
        # Watermark HELD on purpose: surface loudly so it gets a manual --backfill.
        reason = "gap >1000 commits since last run" if status == "INCOMPLETE" else "a detail fetch failed"
        note = (f"PARTIAL ({scored} scored) — last_sha HELD for retry ({reason}); "
                f"run: commit-monitor.py --repo {repo} --backfill 200")
    else:
        st["last_sha"] = head
        note = f"scored {scored} non-merge commit(s), skipped {n_merges} merge(s)"
    return findings, note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backfill", type=int, default=0,
                    help="score the last N commits per repo (first-run/demo)")
    ap.add_argument("--repo", help="limit to one owner/name")
    ap.add_argument("--min-score", type=int, default=3)
    ap.add_argument("--no-save", action="store_true", help="don't update state")
    args = ap.parse_args()

    wl = load_json(WATCHLIST, None)
    if wl is None:
        print(f"!! no watchlist at {WATCHLIST}", file=sys.stderr)
        sys.exit(1)
    repos = wl["repos"] if isinstance(wl, dict) else wl
    if args.repo:
        repos = [r for r in repos if r["repo"] == args.repo]

    for r in repos:
        p = r.get("profile")
        if p and p not in PROFILES:
            print(f"!! {r['repo']}: unknown profile {p!r}, falling back to "
                  f"{DEFAULT_PROFILE!r} (valid: {', '.join(PROFILES)})", file=sys.stderr)

    state = load_json(STATE, {})
    all_findings, notes = [], []
    for entry in repos:
        f, note = process_repo(entry, state, args.backfill, args.min_score)
        all_findings.extend(f)
        if note:
            notes.append(f"  {entry['repo']}: {note}")
        if note == "RATE_LIMIT":
            print(f"!! GitHub rate limit hit on {entry['repo']} -- watermark HELD; "
                  f"set GITHUB_TOKEN and re-run.", file=sys.stderr)
            break
        if note.startswith("PARTIAL"):
            # loud, per the no-silent-gaps rule: a commit was NOT scored this run
            print(f"!! {entry['repo']}: {note}", file=sys.stderr)
        time.sleep(0.3)

    # Rank: security-FIX commits first, then by score, then newest within a tie
    # (two stable sorts: date desc, then the primary key).
    all_findings.sort(key=lambda x: x.get("date", ""), reverse=True)
    all_findings.sort(key=lambda x: (-int(bool(x.get("is_fix"))), -x["score"]))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    lines = [f"# commit-monitor digest {ts}", ""]
    if all_findings:
        lines.append(f"{len(all_findings)} security-relevant new commit(s), ranked:\n")
        for x in all_findings:
            if x.get("is_fix"):
                tag = "🔴 SECURITY-FIX → variant-analysis (hunt the un-fixed siblings)"
            elif x["score"] >= 6:
                tag = "🟠 risky new code → review the new attack surface"
            else:
                tag = "🟡 review"
            lines.append(f"## [{x['score']}] {tag} — {x['repo']} `{x['sha']}`")
            lines.append(f"- **{x['subject']}**")
            lines.append(f"- {x['program']} · {x.get('profile', '?')} · {x['date']} · {x['author']}")
            lines.append(f"- {x['url']}")
            for r in x["reasons"]:
                lines.append(f"  - {r}")
            lines.append("")
    else:
        lines.append("No security-relevant new commits this run.\n")
    if notes:
        lines.append("## Notes")
        lines.extend(notes)
    digest = "\n".join(lines)
    print(digest)

    if all_findings:
        os.makedirs(DIGEST_DIR, exist_ok=True)
        dpath = os.path.join(DIGEST_DIR, f"digest-{ts}.md")
        with open(dpath, "w") as f:
            f.write(digest)
        print(f"\n[saved: {dpath}]", file=sys.stderr)

    if not args.no_save:
        save_json(STATE, state)


if __name__ == "__main__":
    main()
