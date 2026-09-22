import importlib.util
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse


SCRIPT = Path(__file__).parents[1] / "bin" / "commit-monitor.py"
SPEC = importlib.util.spec_from_file_location("commit_monitor", SCRIPT)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


def commit(sha, parents=1, message="change"):
    return {
        "sha": sha,
        "parents": [{"sha": f"parent-{i}"} for i in range(parents)],
        "commit": {
            "message": message,
            "author": {"date": "2026-08-23T00:00:00Z", "name": "Researcher"},
        },
    }


def gitlab_commit(sha, parents=1, message="change"):
    return {
        "id": sha,
        "parent_ids": [f"parent-{i}" for i in range(parents)],
        "message": message,
        "authored_date": "2026-09-22T00:00:00Z",
        "author_name": "Researcher",
        "web_url": f"https://gitlab.com/group/project/-/commit/{sha}",
    }


def normalized_commit(sha, parents=1, message="change"):
    return {
        "sha": sha,
        "parents": [f"parent-{i}" for i in range(parents)],
        "message": message,
        "date": "2026-09-22T00:00:00Z",
        "author": "Researcher",
        "url": f"https://github.com/owner/repo/commit/{sha}",
    }


class CommitCollectionTests(unittest.TestCase):
    def test_backfill_spans_multiple_pages_and_ignores_watermark(self):
        pages = {
            1: [commit(f"sha-{i}") for i in range(100)],
            2: [commit(f"sha-{i}") for i in range(100, 200)],
        }
        requested = []

        def fake_get(path):
            page = int(parse_qs(urlparse(path).query)["page"][0])
            requested.append(page)
            return pages[page], None

        with mock.patch.object(monitor, "gh_get", side_effect=fake_get):
            commits, head, status = monitor.gh_commits_since(
                "owner/repo", "sha-5", backfill=150
            )

        self.assertEqual([1, 2], requested)
        self.assertEqual(150, len(commits))
        self.assertEqual("sha-0", head)
        self.assertIsNone(status)

    def test_normal_scan_stops_at_saved_watermark(self):
        batch = [commit("new"), commit("saved"), commit("older")]
        with mock.patch.object(monitor, "gh_get", return_value=(batch, None)):
            commits, head, status = monitor.gh_commits_since(
                "owner/repo", "saved", backfill=0
            )

        self.assertEqual(["new"], [item["sha"] for item in commits])
        self.assertEqual("new", head)
        self.assertIsNone(status)

    def test_gitlab_scan_encodes_nested_project_and_normalizes_commits(self):
        requested = []

        def fake_get(path):
            requested.append(path)
            return [gitlab_commit("new"), gitlab_commit("saved")], None

        with mock.patch.object(monitor, "gl_get", side_effect=fake_get):
            commits, head, status = monitor.gl_commits_since(
                "group/subgroup/project", "saved", backfill=0, branch="main"
            )

        self.assertEqual(["new"], [item["sha"] for item in commits])
        self.assertEqual("new", head)
        self.assertIsNone(status)
        self.assertIn("group%2Fsubgroup%2Fproject", requested[0])
        self.assertIn("ref_name=main", requested[0])

    def test_missing_watermark_is_a_coverage_error(self):
        with mock.patch.object(
            monitor,
            "gh_get",
            return_value=([commit("new"), commit("older")], None),
        ):
            _, _, status = monitor.gh_commits_since(
                "owner/repo", "rewritten-away", backfill=0
            )

        self.assertEqual("WATERMARK_MISSING", status)


class RepositoryProcessingTests(unittest.TestCase):
    def test_merge_commit_is_scored_and_provider_state_advances(self):
        merged = normalized_commit(
            "merged", parents=2, message="Fix invalid consensus frame"
        )
        files = [{
            "filename": "src/consensus/handler.rs",
            "status": "modified",
            "patch": '+panic!("invalid block")',
        }]
        state = {"owner/repo": {"last_sha": "old"}}

        with (
            mock.patch.object(
                monitor, "commits_since", return_value=([merged], "merged", None)
            ),
            mock.patch.object(monitor, "commit_files", return_value=(files, None)),
            mock.patch.object(monitor.time, "sleep"),
        ):
            findings, note = monitor.process_repo(
                {
                    "provider": "github",
                    "repo": "owner/repo",
                    "program": "Program",
                    "reward": "bounty",
                    "profile": "blockchain",
                },
                state,
                backfill=0,
                min_score=3,
            )

        self.assertEqual(1, len(findings))
        self.assertEqual("patch", findings[0]["kind"])
        self.assertEqual("merged", state["owner/repo"]["last_sha"])
        self.assertIn("including 1 merge(s)", note)

    def test_new_web_controller_is_classified_as_new_surface(self):
        score, reasons, kind = monitor.score_commit(
            "Add account export",
            [{
                "filename": "app/controllers/export_controller.py",
                "status": "added",
                "patch": "+def export_account():\n+    return account_data",
            }],
            "web",
        )

        self.assertGreaterEqual(score, 3)
        self.assertEqual("new_surface", kind)
        self.assertTrue(any("new attack-surface file" in reason for reason in reasons))

    def test_new_test_file_is_not_attack_surface(self):
        _, reasons, kind = monitor.score_commit(
            "Add topic publisher coverage",
            [{
                "filename": "spec/services/topic_publisher_message_bus_spec.rb",
                "status": "added",
                "patch": "+describe TopicPublisher",
            }],
            "web",
        )

        self.assertEqual("review", kind)
        self.assertFalse(any("new attack-surface file" in reason for reason in reasons))

    def test_ordinary_patch_is_not_mislabeled_as_security_fix(self):
        score, _, kind = monitor.score_commit(
            "Fix incorrect parser length",
            [{
                "filename": "src/protocol/parser.c",
                "status": "modified",
                "patch": "+if (length > remaining) return ERROR;",
            }],
            "systems",
        )

        self.assertGreaterEqual(score, 3)
        self.assertEqual("patch", kind)

    def test_explicit_security_patch_gets_highest_classification(self):
        score, reasons, kind = monitor.score_commit(
            "Fix authentication bypass in API tokens",
            [{
                "filename": "app/controllers/api/tokens_controller.rb",
                "status": "modified",
                "patch": "+authorize! token",
            }],
            "web",
        )

        self.assertGreaterEqual(score, 6)
        self.assertEqual("security_fix", kind)
        self.assertTrue(any("explicit security-fix" in reason for reason in reasons))

    def test_security_signal_in_body_upgrades_generic_fix_subject(self):
        _, _, kind = monitor.score_commit(
            "Fix scoped topic broadcasts\n\nPrevents disclosure of restricted metadata.",
            [{
                "filename": "lib/topic_publisher.rb",
                "status": "modified",
                "patch": "+MessageBus.publish(channel, secure_audience)",
            }],
            "web",
        )

        self.assertEqual("security_fix", kind)

    def test_gitlab_diff_is_normalized_for_common_scoring(self):
        response = [{
            "old_path": "old.rb",
            "new_path": "app/controllers/new_controller.rb",
            "new_file": True,
            "deleted_file": False,
            "renamed_file": False,
            "diff": "@@ -0,0 +1 @@\n+class NewController",
            "collapsed": False,
            "too_large": False,
        }]
        with mock.patch.object(monitor, "gl_get", return_value=(response, None)):
            files, error = monitor.gl_commit_files("gitlab-org/gitlab", "abc")

        self.assertIsNone(error)
        self.assertEqual("added", files[0]["status"])
        self.assertEqual("app/controllers/new_controller.rb", files[0]["filename"])


class DigestTests(unittest.TestCase):
    def test_issue_body_is_bounded_and_links_complete_digest(self):
        run_url = "https://github.com/owner/repo/actions/runs/123"
        body = monitor.bounded_issue_body("x" * 1_000, run_url, limit=300)

        self.assertLessEqual(len(body), 300)
        self.assertIn("Digest truncated", body)
        self.assertIn(run_url, body)

    def test_short_issue_body_is_unchanged(self):
        digest = "# digest\n\nNo findings."

        self.assertEqual(digest, monitor.bounded_issue_body(digest))


class ConfigurationTests(unittest.TestCase):
    def test_invalid_and_duplicate_targets_are_rejected(self):
        errors = monitor.validate_repos([
            {"provider": "github", "repo": "owner/repo", "profile": "web"},
            {"provider": "github", "repo": "owner/repo", "profile": "web"},
            {"provider": "github", "repo": "missing-slash", "profile": "web"},
            {"provider": "other", "repo": "other/repo", "profile": "web"},
            {"provider": "github", "repo": "profile/repo", "profile": "unknown"},
            {"provider": "github", "repo": "reward/repo", "reward": "unknown"},
        ])

        self.assertTrue(any("duplicate target" in error for error in errors))
        self.assertTrue(any("invalid repo" in error for error in errors))
        self.assertTrue(any("unknown provider" in error for error in errors))
        self.assertTrue(any("unknown profile" in error for error in errors))
        self.assertTrue(any("unknown reward" in error for error in errors))

    def test_provider_namespaces_have_distinct_state_keys(self):
        self.assertEqual(
            "gitlab:group/subgroup/project",
            monitor.target_key({
                "provider": "gitlab",
                "repo": "group/subgroup/project",
            }),
        )
        self.assertEqual(
            "owner/repo",
            monitor.target_key({"provider": "github", "repo": "owner/repo"}),
        )

    def test_partial_and_api_failures_are_coverage_errors(self):
        self.assertFalse(monitor.note_is_error("no new commits"))
        self.assertFalse(monitor.note_is_error("scored 2 commit(s), including 1 merge(s)"))
        self.assertTrue(monitor.note_is_error("HTTP 404"))
        self.assertTrue(monitor.note_is_error("PARTIAL (2 scored)"))


if __name__ == "__main__":
    unittest.main()
