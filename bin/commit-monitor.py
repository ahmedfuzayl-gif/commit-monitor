#!/usr/bin/env python3
"""
commit-monitor: the source-code sibling of monitor.sh.

Philosophy (same as this workspace): be FIRST to new attack surface. For source
review that means reviewing NEW COMMITS the moment they land -- before the
vendor's own security team and other hunters get to them. Stable, released code
is already audited and duplicate-prone; the fresh delta is where an
undiscovered, un-raced bug lives.

What it does:
  * Watches active OSS security-program repositories from GitHub and GitLab.
  * Fetches every default-branch commit since the last-seen SHA and holds the
    watermark whenever collection is incomplete.
  * Separately identifies explicit security fixes, ordinary bug-fix patches,
    and newly introduced attack surface.
  * Scores each delta with target-specific web, systems, desktop, blockchain,
    or generic security vocabulary.
  * Emits a ranked markdown digest for reachability-first manual review.

Usage:
  commit-monitor.py
  commit-monitor.py --backfill 40 --no-save
  commit-monitor.py --repo gitlab-org/gitlab --backfill 20 --no-save
  commit-monitor.py --reward bounty --min-score 4

Auth: GITHUB_TOKEN raises GitHub's API limit. GITLAB_TOKEN is optional for
public GitLab.com projects and useful for larger backfills.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ~/bounty
WATCHLIST = os.path.join(BASE, "watchlist.json")
STATE_DIR = os.path.join(BASE, "commit-monitor")
STATE = os.path.join(STATE_DIR, "state.json")
DIGEST_DIR = os.path.join(STATE_DIR, "digests")
GITHUB_API = "https://api.github.com"
GITLAB_API = "https://gitlab.com/api/v4"
PROVIDERS = ("github", "gitlab")
REWARD_TYPES = ("bounty", "vdp")
ISSUE_BODY_LIMIT = 60_000


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

# ---- message and code-delta signals ----------------------------------------
# Explicit vulnerability language. These terms alone are security context, not
# proof that an ordinary "validate"/"panic"/"consensus" commit is a security fix.
SECURITY_WORDS = [
    "security", "vuln", "cve", "advisory", "exploit", "attacker", "malicious",
    "bypass", "unauthoriz", "privilege escalat", "account takeover",
    "injection", "ssrf", "rce", "xss", "csrf", "idor", "sqli", "ssti", "xxe",
    "prototype pollution", "request smuggling", "path traversal", "open redirect",
    "disclos", "data leak", "credential leak", "secret leak", "exfiltrat",
    "double-spend", "double spend", "nonce reuse", "signature forg",
]

# Patch language is deliberately separate from SECURITY_WORDS. Most fixes are
# worth variant review, but must not be mislabeled as disclosed vulnerabilities.
PATCH_WORDS = [
    "fix", "bug", "prevent", "avoid", "harden", "mitigat", "incorrect", "wrong",
    "mishandl", "regression", "edge case", "panic", "crash", "overflow",
    "underflow", "oob", "out-of-bounds", "out of bounds", "bounds check",
    "deadlock", "hang", "unbounded", "exhaust", "oom", "memory leak",
    "malformed", "reject", "sanitiz", "validat", "unchecked", "race condition",
    "use-after-free", "double free", "null deref", "nondeterministic",
]

FEATURE_WORDS = [
    "add ", "adds ", "added ", "introduc", "implement", "support ", "enable ",
    "expose ", "new ", "allow ", "create ", "initial ",
]

# ---- per-target profiles ---------------------------------------------------
_BLOCKCHAIN_PATHS = [
    "consensus", "crypto", "/sig", "signature", "/key", "p2p", "/net",
    "rpc", "/api", "api/", "mempool", "txpool", "/tx", "/vm", "evm", "/state",
    "validator", "stake", "slash", "/gov", "/bank", "ibc", "bridge",
    "serde", "codec", "decode", "deserial", "rlp", "ssz", "borsh", "proto",
    "verify", "/auth", "auth/", "gas", "fee", "wallet",
]
_BLOCKCHAIN_FLAGS = [
    ".unwrap(", ".expect(", "panic!(", "unreachable!(", "unsafe ",
    "unchecked", "get_unchecked", "transmute", "from_raw", "as usize",
    "as u64", "as u32", "as i64", "memcpy", "while true", "loop {",
    "saturating_", "wrapping_", "overflowing_", "recover(", "ecrecover",
    "assert(", "require(",
]

_WEB_PATHS = [
    "controller", "api/", "/api", "route", "handler", "graphql", "resolver",
    "mutation", "auth/", "/auth", "session", "admin", "middleware", "policy",
    "serializer", "webhook", "upload", "download", "storage", "template",
    "render", "redirect", "oauth", "saml", "sso", "jwt", "password", "login",
    "account", "permission", "acl", "csrf", "cors", "import", "export",
    "proxy", "/url", "/file", "settings", "models/", "views/", "query",
    "service", "worker", "job", "integration", "plugin", "extension", "ai/",
]
_WEB_FLAGS = [
    # command / code execution
    "system(", "exec(", "eval(", "popen(", "subprocess", "child_process",
    "os.system", "shell_exec", "proc_open", "runtime.getruntime",
    "processbuilder", "new function(", "spawn(", "execsync(",
    # SQL and unsafe deserialization
    ".raw(", "find_by_sql", "createquerybuilder", "sequelize.query",
    "executequery(", "rawquery(", "string.format", "pickle.loads", "yaml.load",
    "marshal.load", "unserialize(", "readobject", "objectinputstream",
    # HTML / template injection
    "html_safe", "dangerouslysetinnerhtml", ".innerhtml", "v-html",
    "mark_safe", "bypasssecuritytrust", "markup(", "|safe",
    # outbound requests and file access
    "send_file", "sendfile", "path.join(", "file.read", "readfilesync(",
    "requests.get(", "urllib.request", "fetch(", "curl_exec", "http.get(",
    # authorization weakening
    "skip_before_action", "skip_authorization", "permit!", "verify=false",
    "verify: false", "insecureskipverify", "jwt.decode", "params.require",
    # route / endpoint declarations
    "resources :", "namespace :", "@app.route", "@router.", "route::",
    "@getmapping", "@postmapping", "@requestmapping", "app.get(", "app.post(",
    "router.get(", "router.post(", "addroute", ".route(", "mount ",
]

_SYSTEMS_PATHS = [
    "parser", "parse", "protocol", "packet", "frame", "codec", "decode",
    "deserial", "network", "/net", "http", "tls", "ssl", "crypto", "auth",
    "permission", "privilege", "sandbox", "process", "command", "exec", "shell",
    "archive", "compress", "extract", "upload", "download", "storage", "ipc",
    "rpc", "proxy", "socket", "ssh", "path", "file", "memory", "allocator",
]
_SYSTEMS_FLAGS = [
    "unsafe ", "memcpy(", "memmove(", "strcpy(", "strcat(", "sprintf(",
    "malloc(", "calloc(", "realloc(", "free(", "from_raw", "transmute",
    "get_unchecked", ".unwrap(", ".expect(", "panic!(", "assert(",
    "reinterpret_cast", "static_cast", "system(", "exec", "popen(",
    "subprocess", "processbuilder", "shell=true", "insecureskipverify",
]

_DESKTOP_PATHS = [
    "renderer", "browser", "extension", "webview", "webcontents", "ipc",
    "preload", "deeplink", "deep-link", "protocol", "navigation", "download",
    "permission", "wallet", "sign", "keyring", "secret", "clipboard",
]
_DESKTOP_FLAGS = [
    "nodeintegration: true", "contextisolation: false", "sandbox: false",
    "websecurity: false", "allowrunninginsecurecontent", "executejavascript(",
    "openexternal(", "setwindowopenhandler", "ipcmain.handle", "ipcrenderer.send",
    "postmessage(", "addEventListener(\"message", "addeventlistener('message",
]

PROFILES = {
    "blockchain": {"paths": _BLOCKCHAIN_PATHS, "flags": _BLOCKCHAIN_FLAGS},
    "web": {"paths": _WEB_PATHS, "flags": _WEB_FLAGS},
    "systems": {"paths": _SYSTEMS_PATHS, "flags": _SYSTEMS_FLAGS},
    "desktop": {
        "paths": sorted(set(_DESKTOP_PATHS) | set(_WEB_PATHS) | set(_SYSTEMS_PATHS)),
        "flags": sorted(set(_DESKTOP_FLAGS) | set(_WEB_FLAGS) | set(_SYSTEMS_FLAGS)),
    },
    "generic": {
        "paths": sorted(
            set(_BLOCKCHAIN_PATHS) | set(_WEB_PATHS) | set(_SYSTEMS_PATHS)
        ),
        "flags": sorted(
            set(_BLOCKCHAIN_FLAGS) | set(_WEB_FLAGS) | set(_SYSTEMS_FLAGS)
        ),
    },
}
DEFAULT_PROFILE = "generic"

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


def _json_get(url, headers, token=None, token_header="Authorization",
              token_prefix="Bearer ", _tries=3):
    last = None
    for attempt in range(_tries):
        req = urllib.request.Request(url, headers=headers)
        if token:
            req.add_header(token_header, token_prefix + token)
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                return json.load(response), None
        except urllib.error.HTTPError as error:
            body = error.read().decode(errors="ignore").lower()
            remaining = error.headers.get("X-RateLimit-Remaining")
            if (error.code in (403, 429) and
                    (remaining == "0" or "rate limit" in body or "abuse" in body
                     or "secondary rate" in body or "too many requests" in body)):
                return None, "RATE_LIMIT"
            if 500 <= error.code < 600 and attempt + 1 < _tries:
                last = f"HTTP {error.code}"
                time.sleep(1.5 * (attempt + 1))
                continue
            return None, f"HTTP {error.code}"
        except Exception as error:
            last = str(error)
            time.sleep(1.5 * (attempt + 1))
    return None, last


def gh_get(path, _tries=3):
    url = path if path.startswith("http") else GITHUB_API + path
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    return _json_get(url, {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "commit-monitor",
    }, token=token, _tries=_tries)


def gl_get(path, _tries=3):
    url = path if path.startswith("http") else GITLAB_API + path
    token = os.environ.get("GITLAB_TOKEN") or os.environ.get("GL_TOKEN")
    return _json_get(url, {
        "Accept": "application/json",
        "User-Agent": "commit-monitor",
    }, token=token, token_header="PRIVATE-TOKEN", token_prefix="", _tries=_tries)


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


def bounded_issue_body(digest, run_url="", limit=ISSUE_BODY_LIMIT):
    """Keep alerts below GitHub's 65,536-character Issue body limit."""
    if len(digest) <= limit:
        return digest
    footer = (
        "\n\n---\nDigest truncated to fit GitHub's Issue limit. "
        "The complete digest is stored in `commit-monitor/digests/`."
    )
    if run_url:
        footer += f" Workflow run: {run_url}"
    if len(footer) >= limit:
        return footer[:limit]
    return digest[:limit - len(footer)].rstrip() + footer


def score_commit(message, files, profile=None):
    """Return ``(score, reasons, kind)`` for one normalized commit diff.

    ``kind`` is one of ``security_fix``, ``patch``, ``new_surface``, or
    ``review``. Ordinary bug fixes are intentionally not called security fixes.
    """
    profile_name = profile if profile in PROFILES else DEFAULT_PROFILE
    hot_paths = PROFILES[profile_name]["paths"]
    code_flags = PROFILES[profile_name]["flags"]

    reasons = []
    score = 0
    full_message = message.lower()
    subject = full_message.split("\n", 1)[0][:200]
    body = full_message[len(subject):][:2000]
    is_noise = (
        subject.startswith(NEG_PREFIXES)
        or any(word in subject for word in NEG_WORDS)
    )

    security_hits = _wordmatch(SECURITY_WORDS, subject)
    body_security_hits = [
        word for word in _wordmatch(SECURITY_WORDS, body)
        if word not in security_hits
    ]
    patch_hits = _wordmatch(PATCH_WORDS, subject)
    feature_hits = _wordmatch(FEATURE_WORDS, subject)
    cves = sorted(set(re.findall(r"cve-\d{4}-\d{4,7}", full_message)))
    disclosure_terms = {"advisory", "vuln", "cve"}
    is_security_fix = bool(
        cves
        or disclosure_terms.intersection(security_hits)
        or (patch_hits and (security_hits or body_security_hits))
    )

    def is_noise_file(filename):
        filename = filename.lower()
        return bool(re.search(
            r"(_test\.|_spec\.|\.test\.|\.spec\.|(^|/)tests?/"
            r"|(^|/)spec/|(^|/)test_|tests?\.rs$"
            r"|(^|/)mocks?/|(^|/)fixtures?/|(^|/)testdata/"
            r"|\.pb\.go$|_pb2\.py$|\.generated\.|(^|/)vendor/"
            r"|(^|/)node_modules/|\.md$|\.txt$|\.lock$|\.snap$"
            r"|(^|/)docs?/|(^|/)wasm/|wasm-browser|wasm-nodejs"
            r"|_bg\.wasm|\.wasm$|\.d\.ts$|uniffi|ffi\.|\.udl$"
            r"|xcframework|/jnilibs/|\.framework/|_generated\."
            r"|(^|/)generated/|\.min\.js$)",
            filename,
        ))

    code_hits = set()
    lines_added = 0
    new_surface_files = []
    relevant_files = []
    for file_change in files:
        filename = file_change.get("filename", "")
        if is_noise_file(filename):
            continue
        relevant_files.append(file_change)
        lowered_filename = filename.lower()
        if (file_change.get("status") == "added"
                and any(path in lowered_filename for path in hot_paths)):
            new_surface_files.append(filename)
        for line in (file_change.get("patch", "") or "").split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                lines_added += 1
                added_line = line[1:].lower()
                for flag in code_flags:
                    if flag.lower() in added_line:
                        code_hits.add(flag.lower())

    path_hits = sorted({
        path.strip("/")
        for file_change in relevant_files
        for path in hot_paths
        if path in file_change.get("filename", "").lower()
    })
    feature_surface = bool(feature_hits and path_hits)

    if is_security_fix:
        score += 6
        signal_hits = security_hits or body_security_hits
        if signal_hits:
            reasons.append("explicit security-fix signal: " + ", ".join(signal_hits[:5]))
    elif security_hits or body_security_hits:
        score += 2
        reasons.append(
            "security context: " + ", ".join((security_hits + body_security_hits)[:5])
        )

    if patch_hits:
        score += 3 + min(len(patch_hits), 2)
        reasons.append("patch signal: " + ", ".join(patch_hits[:5]))

    if cves:
        score += 3
        reasons.append("CVE referenced: " + ", ".join(cves[:4]))

    if code_hits:
        score += min(2 * len(code_hits), 6)
        reasons.append("risky added code: " + ", ".join(sorted(code_hits)[:6]))

    if new_surface_files:
        score += 2 + min(len(new_surface_files), 2)
        reasons.append(
            "new attack-surface file: "
            + ", ".join(os.path.basename(path) for path in new_surface_files[:3])
        )

    if feature_surface:
        score += 2
        reasons.append("feature introduction: " + ", ".join(feature_hits[:3]))

    has_primary_signal = bool(
        security_hits or body_security_hits or patch_hits or code_hits
        or new_surface_files or feature_surface
    )
    if path_hits and has_primary_signal:
        score += min(len(path_hits), 3)
        reasons.append("hot paths: " + ", ".join(path_hits[:6]))
    elif path_hits:
        reasons.append(
            "touches " + ", ".join(path_hits[:4]) + " without a primary signal"
        )

    if ((is_security_fix or patch_hits)
            and 0 < lines_added <= 40 and len(relevant_files) <= 4):
        score += 2
        reasons.append("small focused patch -> variant-review target")

    if is_noise:
        score = max(0, score - 4)
        reasons.append("down-weighted: cleanup/docs/test/dependency noise")

    if is_security_fix:
        kind = "security_fix"
    elif patch_hits:
        kind = "patch"
    elif code_hits or new_surface_files or feature_surface:
        kind = "new_surface"
    else:
        kind = "review"
    return score, reasons, kind


def _normalize_github_commit(item, repo):
    metadata = item.get("commit") or {}
    author = metadata.get("author") or metadata.get("committer") or {}
    return {
        "sha": item["sha"],
        "parents": [parent.get("sha") for parent in item.get("parents", [])],
        "message": metadata.get("message", ""),
        "date": author.get("date", ""),
        "author": author.get("name", "unknown"),
        "url": item.get("html_url") or f"https://github.com/{repo}/commit/{item['sha']}",
    }


def _normalize_gitlab_commit(item, repo):
    return {
        "sha": item["id"],
        "parents": item.get("parent_ids", []),
        "message": item.get("message") or item.get("title", ""),
        "date": item.get("authored_date") or item.get("committed_date", ""),
        "author": item.get("author_name", "unknown"),
        "url": item.get("web_url")
               or f"https://gitlab.com/{repo}/-/commit/{item['id']}",
    }


def _collect_commits(fetch_page, normalize, last_sha, backfill, cap_pages):
    """Collect normalized commits newest-first without crossing a saved SHA."""
    new, head = [], None
    forced_backfill = backfill > 0
    max_pages = max(1, (backfill + 99) // 100) if forced_backfill else cap_pages
    for page in range(1, max_pages + 1):
        batch, error = fetch_page(page)
        if error:
            return new, head, error
        if not batch:
            if last_sha and not forced_backfill:
                return new, head, "WATERMARK_MISSING"
            return new, head, None
        commits = [normalize(item) for item in batch]
        if head is None:
            head = commits[0]["sha"]
        for commit in commits:
            if not forced_backfill and last_sha and commit["sha"] == last_sha:
                return new, head, None
            new.append(commit)
            if forced_backfill and len(new) >= backfill:
                return new[:backfill], head, None
        if len(batch) < 100:
            if last_sha and not forced_backfill:
                return new, head, "WATERMARK_MISSING"
            return new, head, None
    if forced_backfill:
        return new[:backfill], head, None
    return new, head, "INCOMPLETE"


def gh_commits_since(repo, last_sha, backfill, cap_pages=10, branch=None):
    def fetch_page(page):
        query = {"per_page": 100, "page": page}
        if branch:
            query["sha"] = branch
        return gh_get(f"/repos/{repo}/commits?{urllib.parse.urlencode(query)}")

    return _collect_commits(
        fetch_page,
        lambda item: _normalize_github_commit(item, repo),
        last_sha,
        backfill,
        cap_pages,
    )


def gl_commits_since(repo, last_sha, backfill, cap_pages=10, branch=None):
    project = urllib.parse.quote(repo, safe="")

    def fetch_page(page):
        query = {"per_page": 100, "page": page}
        if branch:
            query["ref_name"] = branch
        return gl_get(
            f"/projects/{project}/repository/commits?{urllib.parse.urlencode(query)}"
        )

    return _collect_commits(
        fetch_page,
        lambda item: _normalize_gitlab_commit(item, repo),
        last_sha,
        backfill,
        cap_pages,
    )


def target_provider(entry):
    return entry.get("provider", "github")


def target_key(entry):
    provider = target_provider(entry)
    return entry["repo"] if provider == "github" else f"{provider}:{entry['repo']}"


def commits_since(entry, last_sha, backfill, cap_pages=10):
    args = (
        entry["repo"],
        last_sha,
        backfill,
        cap_pages,
        entry.get("branch"),
    )
    if target_provider(entry) == "gitlab":
        return gl_commits_since(*args)
    return gh_commits_since(*args)


def gh_commit_files(repo, sha, cap_pages=10):
    files = []
    for page in range(1, cap_pages + 1):
        detail, error = gh_get(
            f"/repos/{repo}/commits/{sha}?per_page=100&page={page}"
        )
        if error:
            return files, error
        batch = detail.get("files", [])
        files.extend(batch)
        if len(batch) < 100:
            return files, None
    return files, "DIFF_TRUNCATED"


def gl_commit_files(repo, sha, cap_pages=10):
    project = urllib.parse.quote(repo, safe="")
    files = []
    for page in range(1, cap_pages + 1):
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        batch, error = gl_get(
            f"/projects/{project}/repository/commits/{sha}/diff?{query}"
        )
        if error:
            return files, error
        files.extend({
            "filename": item.get("new_path") or item.get("old_path", ""),
            "status": (
                "added" if item.get("new_file")
                else "removed" if item.get("deleted_file")
                else "renamed" if item.get("renamed_file")
                else "modified"
            ),
            "patch": item.get("diff", ""),
            "patch_limited": bool(item.get("collapsed") or item.get("too_large")),
        } for item in batch)
        if len(batch) < 100:
            return files, None
    return files, "DIFF_TRUNCATED"


def commit_files(entry, sha, cap_pages=10):
    if target_provider(entry) == "gitlab":
        return gl_commit_files(entry["repo"], sha, cap_pages)
    return gh_commit_files(entry["repo"], sha, cap_pages)


def process_repo(entry, state, backfill, min_score, cap_pages=10):
    repo = entry["repo"]
    provider = target_provider(entry)
    key = target_key(entry)
    program = entry.get("program", "?")
    target_state = state.setdefault(key, {})
    last = target_state.get("last_sha")

    if last is None and not backfill:
        commits, head, error = commits_since(entry, None, 1, cap_pages)
        if error:
            return [], error
        if not commits or head is None:
            return [], "no commits"
        target_state["last_sha"] = head
        target_state["last_checked_at"] = datetime.now(timezone.utc).isoformat()
        return [], "BASELINED (run again after new commits, or use --backfill)"

    new, head, status = commits_since(entry, last, backfill, cap_pages)
    collection_gap = status in ("INCOMPLETE", "WATERMARK_MISSING")
    if status and not collection_gap:
        return [], status
    if head is None:
        return [], "no commits"
    if not new:
        target_state["last_sha"] = head
        target_state["last_checked_at"] = datetime.now(timezone.utc).isoformat()
        return [], "no new commits"

    findings = []
    merge_count = 0
    incomplete = collection_gap
    for commit in new:
        if len(commit.get("parents", [])) > 1:
            merge_count += 1
        files, error = commit_files(entry, commit["sha"], cap_pages)
        if error == "RATE_LIMIT":
            return findings, "RATE_LIMIT"
        if error:
            incomplete = True
        score, reasons, kind = score_commit(
            commit["message"], files, entry.get("profile")
        )
        limited = sum(1 for item in files if item.get("patch_limited"))
        if limited:
            reasons.append(f"{limited} GitLab patch(es) omitted by provider size limits")
        if score >= min_score:
            findings.append({
                "repo": repo,
                "provider": provider,
                "program": program,
                "reward": entry.get("reward", "vdp"),
                "profile": entry.get("profile") or DEFAULT_PROFILE,
                "sha": commit["sha"][:10],
                "url": commit["url"],
                "date": commit["date"],
                "author": commit["author"],
                "subject": commit["message"].split("\n")[0][:120],
                "score": score,
                "reasons": reasons,
                "kind": kind,
            })
        time.sleep(0.15)

    scored = len(new)
    if incomplete:
        if status == "INCOMPLETE":
            reason = f"gap >{cap_pages * 100} commits since last run"
        elif status == "WATERMARK_MISSING":
            reason = "saved watermark is no longer reachable"
        else:
            reason = "a commit diff fetch failed or was truncated"
        retry_pages = max(20, cap_pages * 2)
        note = (f"PARTIAL ({scored} scored) — last_sha HELD for retry ({reason}); "
                f"run: commit-monitor.py --repo {repo} --max-pages {retry_pages}")
    else:
        target_state["last_sha"] = head
        target_state["last_checked_at"] = datetime.now(timezone.utc).isoformat()
        note = f"scored {scored} commit(s), including {merge_count} merge(s)"
    return findings, note


def validate_repos(repos):
    """Return actionable configuration errors instead of silently omitting targets."""
    if not isinstance(repos, list):
        return ["watchlist 'repos' must be a list"]
    errors, seen = [], set()
    for index, entry in enumerate(repos):
        if not isinstance(entry, dict):
            errors.append(f"entry {index} must be an object")
            continue
        repo = entry.get("repo")
        if (not isinstance(repo, str)
                or not re.fullmatch(r"[^/\s]+(?:/[^/\s]+)+", repo)):
            errors.append(
                f"entry {index} has invalid repo {repo!r}; expected namespace/name"
            )
            continue
        provider = entry.get("provider", "github")
        if provider not in PROVIDERS:
            errors.append(
                f"{repo}: unknown provider {provider!r}; valid: {', '.join(PROVIDERS)}"
            )
        key = (provider, repo)
        if key in seen:
            errors.append(f"duplicate target: {provider}:{repo}")
        seen.add(key)
        profile = entry.get("profile")
        if profile and profile not in PROFILES:
            errors.append(
                f"{repo}: unknown profile {profile!r}; valid: {', '.join(PROFILES)}"
            )
        reward = entry.get("reward")
        if reward and reward not in REWARD_TYPES:
            errors.append(
                f"{repo}: unknown reward {reward!r}; valid: {', '.join(REWARD_TYPES)}"
            )
        branch = entry.get("branch")
        if branch is not None and (not isinstance(branch, str) or not branch.strip()):
            errors.append(f"{repo}: branch must be a non-empty string")
    return errors


def note_is_error(note):
    """True when a target was not completely and reliably monitored."""
    if not note:
        return True
    return not (
        note == "no new commits"
        or note.startswith("scored ")
        or note.startswith("BASELINED ")
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backfill", type=int, default=0,
                    help="score the most recent N commits, ignoring the saved watermark")
    ap.add_argument("--repo", help="limit to one owner/name")
    ap.add_argument("--provider", choices=PROVIDERS,
                    help="limit to one source-code provider")
    ap.add_argument("--reward", choices=REWARD_TYPES,
                    help="limit to bounty or disclosure-only programs")
    ap.add_argument("--min-score", type=int, default=3)
    ap.add_argument("--max-pages", type=int, default=10,
                    help="maximum 100-commit pages used to reach a saved watermark")
    ap.add_argument("--list-targets", action="store_true",
                    help="print every configured target and exit without API calls")
    ap.add_argument("--no-save", action="store_true", help="don't update state")
    ap.add_argument("--issue-output",
                    help="write a GitHub-Issue-safe copy of the digest")
    args = ap.parse_args()
    if args.backfill < 0 or args.max_pages < 1:
        ap.error("--backfill must be >= 0 and --max-pages must be >= 1")

    wl = load_json(WATCHLIST, None)
    if wl is None:
        print(f"!! no watchlist at {WATCHLIST}", file=sys.stderr)
        return 2
    repos = wl.get("repos") if isinstance(wl, dict) else wl
    config_errors = validate_repos(repos)
    if config_errors:
        for error in config_errors:
            print(f"!! {error}", file=sys.stderr)
        return 2

    if args.repo:
        repos = [entry for entry in repos if entry["repo"] == args.repo]
        if not repos:
            print(f"!! configured target not found: {args.repo}", file=sys.stderr)
            return 2
    if args.provider:
        repos = [
            entry for entry in repos
            if entry.get("provider", "github") == args.provider
        ]
    if args.reward:
        repos = [
            entry for entry in repos
            if entry.get("reward", "vdp") == args.reward
        ]

    if args.list_targets:
        for entry in repos:
            print(
                f"{target_provider(entry)}\t{entry['repo']}\t"
                f"{entry.get('profile') or DEFAULT_PROFILE}\t"
                f"{entry.get('reward', 'vdp')}\t{entry.get('program', '?')}"
            )
        print(f"\n{len(repos)} configured target(s)")
        return 0

    state = load_json(STATE, {})
    all_findings, notes, health_errors = [], [], []
    attempted = 0
    rate_limited = set()
    for entry in repos:
        provider = target_provider(entry)
        label = f"{provider}:{entry['repo']}"
        if provider in rate_limited:
            health_errors.append(
                f"{label}: not attempted after {provider} rate limit"
            )
            continue
        attempted += 1
        findings, note = process_repo(
            entry, state, args.backfill, args.min_score, args.max_pages
        )
        all_findings.extend(findings)
        if note:
            notes.append(f"  {label}: {note}")
        if note_is_error(note):
            health_errors.append(f"{label}: {note or 'unknown error'}")
        if note == "RATE_LIMIT":
            rate_limited.add(provider)
            token_name = "GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN"
            print(
                f"!! {provider} rate limit hit on {entry['repo']} -- watermark HELD; "
                f"set {token_name} and re-run.",
                file=sys.stderr,
            )
        if note and note.startswith("PARTIAL"):
            print(f"!! {label}: {note}", file=sys.stderr)
        time.sleep(0.3)

    kind_priority = {
        "security_fix": 0,
        "patch": 1,
        "new_surface": 2,
        "review": 3,
    }
    all_findings.sort(key=lambda finding: finding.get("date", ""), reverse=True)
    all_findings.sort(key=lambda finding: (
        kind_priority.get(finding.get("kind"), 4),
        -finding["score"],
    ))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    lines = [
        f"# commit-monitor digest {ts}",
        "",
        (f"{len(repos)} configured target(s); {attempted} attempted; "
         f"{len(health_errors)} coverage error(s)."),
        "",
    ]
    if all_findings:
        lines.append(f"{len(all_findings)} security-relevant commit lead(s), ranked:\n")
        tags = {
            "security_fix": "[SECURITY FIX] disclosed-fix variant analysis",
            "patch": "[PATCH] bug-fix variant review",
            "new_surface": "[NEW SURFACE] reachability review",
            "review": "[REVIEW]",
        }
        for finding in all_findings:
            tag = tags.get(finding.get("kind"), tags["review"])
            label = f"{finding['provider']}:{finding['repo']}"
            lines.append(
                f"## [{finding['score']}] {tag} — {label} `{finding['sha']}`"
            )
            lines.append(f"- **{finding['subject']}**")
            lines.append(
                f"- {finding['program']} · {finding['reward']} · "
                f"{finding.get('profile', '?')} · {finding['date']} · "
                f"{finding['author']}"
            )
            lines.append(f"- {finding['url']}")
            for reason in finding["reasons"]:
                lines.append(f"  - {reason}")
            lines.append("")
    else:
        lines.append("No security-relevant new commits this run.\n")
    if notes:
        lines.append("## Notes")
        lines.extend(notes)
    if health_errors:
        lines.append("")
        lines.append("## Monitor errors")
        lines.extend(f"- {error}" for error in health_errors)
    digest = "\n".join(lines)
    print(digest)

    if args.issue_output:
        server = os.environ.get("GITHUB_SERVER_URL")
        repository = os.environ.get("GITHUB_REPOSITORY")
        run_id = os.environ.get("GITHUB_RUN_ID")
        run_url = (
            f"{server}/{repository}/actions/runs/{run_id}"
            if server and repository and run_id else ""
        )
        with open(args.issue_output, "w") as issue_file:
            issue_file.write(bounded_issue_body(digest, run_url))

    if all_findings or health_errors:
        os.makedirs(DIGEST_DIR, exist_ok=True)
        dpath = os.path.join(DIGEST_DIR, f"digest-{ts}.md")
        with open(dpath, "w") as f:
            f.write(digest)
        print(f"\n[saved: {dpath}]", file=sys.stderr)

    if not args.no_save:
        save_json(STATE, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
