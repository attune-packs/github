from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

try:
    import requests
except ModuleNotFoundError:
    # Attune's local pack test runner does not install pack requirements.
    requests = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Session:
        def __init__(self):
            self.trust_env = True

        def request(self, *args, **kwargs):
            raise ConnectionError("network unavailable in unit tests")

    requests.RequestException = RequestException
    requests.ConnectionError = ConnectionError
    requests.Session = Session
    requests.Response = object
    requests.structures = types.SimpleNamespace(CaseInsensitiveDict=dict)
    sys.modules["requests"] = requests


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import github_client as github  # noqa: E402


TOKEN = "TOP-SECRET-GITHUB-TOKEN"
OPERATIONS = {
    "artifact_delete", "artifact_download", "artifact_list",
    "branch_create", "branch_delete", "branch_list",
    "comment_create", "comment_delete", "comment_list", "comment_update",
    "commit_get", "commit_list", "commit_status_create", "commit_status_list",
    "content_delete", "content_get", "content_put",
    "deployment_create", "deployment_list", "deployment_status_create", "deployment_status_list",
    "issue_create", "issue_get", "issue_labels_set", "issue_list", "issue_update",
    "label_create", "label_delete", "label_list",
    "protection_delete", "protection_get", "protection_update",
    "pull_create", "pull_get", "pull_list", "pull_merge", "pull_review_create", "pull_review_list", "pull_update",
    "release_asset_delete", "release_asset_download", "release_asset_list", "release_asset_upload",
    "release_create", "release_delete", "release_get", "release_list", "release_update",
    "repository_create", "repository_delete", "repository_get", "repository_list", "repository_update",
    "team_get", "team_list", "team_member_add", "team_member_list", "team_member_remove",
    "webhook_create", "webhook_delete", "webhook_list",
    "workflow_dispatch", "workflow_get", "workflow_list", "workflow_run_control", "workflow_run_get", "workflow_run_list",
}


class Response:
    def __init__(self, value=None, status_code=200, headers=None, raw=None):
        self.status_code = status_code
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.content = json.dumps(value).encode() if raw is None else raw
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset:offset + chunk_size]

    def close(self):
        self.closed = True


def token_credential(**extra):
    return {"auth_type": "token", "token_kind": "fine_grained", "token": TOKEN, **extra}


def client(**extra):
    return github.GitHubClient(token_credential(**extra), timeout_seconds=12, read_retries=1)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_complete_explicit_action_inventory(self):
        self.assertEqual(OPERATIONS, set(self.actions))
        self.assertEqual(67, len(self.actions))

    def test_all_actions_are_flat_structured_and_key_scoped(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"github.{name}",
                    "runner_type": "python",
                    "runtime_version": '">=3.10"',
                    "entry_point": "github_action.py",
                    "parameter_delivery": "stdin",
                    "parameter_format": "json",
                    "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: github\.credentials[^\n]*\}")
                for field in ("operation", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (token|private_key|base_url|webhook_secret):")

    def test_destructive_and_sensitive_contracts_have_confirmation(self):
        confirmed = {
            name for name in OPERATIONS
            if "delete" in name
            or name in {
                "pull_merge", "protection_update", "team_member_add", "team_member_remove",
                "deployment_create", "deployment_status_create", "workflow_dispatch",
                "workflow_run_control", "issue_labels_set", "release_update", "webhook_create",
            }
        }
        for name in confirmed:
            with self.subTest(action=name):
                self.assertRegex(self.actions[name], r"(?m)^  confirmation: \{[^\n]*required: true")

    def test_source_license_api_and_no_event_surface(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn('source_revision: "fc8e45bd25bcfdd891f3e88e0b87f7592fe7f634"', pack)
        self.assertIn('source_version: "2.1.5"', pack)
        self.assertIn('api_version: "2026-03-10"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("fc8e45bd25bcfdd891f3e88e0b87f7592fe7f634", (ROOT / "NOTICE").read_text(encoding="utf-8"))
        self.assertFalse((ROOT / "sensors").exists())
        self.assertFalse((ROOT / "triggers").exists())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("delivery-ID deduplication", readme)
        self.assertIn("deferred", readme)

    def test_dependencies_are_declared_and_pinned_or_bounded(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("attune-sdk @ git+https://", requirements)
        self.assertIn("@841298f132d9f6af6b7afc2f7091db1f3460b9c9", requirements)
        self.assertRegex(requirements, r"requests>=.+,<")
        self.assertRegex(requirements, r"cryptography>=.+,<")


class ClientSecurityTests(unittest.TestCase):
    def test_token_auth_headers_endpoint_timeout_and_no_proxy_or_redirect(self):
        api = client()
        api.session.request = mock.Mock(return_value=Response({"full_name": "acme/widgets"}, headers={
            "ETag": 'W/"one"', "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Used": "1", "X-RateLimit-Reset": "1786795200", "X-RateLimit-Resource": "core",
            "X-GitHub-Request-Id": "SAFE-ID",
        }))
        data, meta = api.request("GET", "/repos/acme/widgets")
        self.assertEqual("acme/widgets", data["full_name"])
        call = api.session.request.call_args
        self.assertEqual(("GET", "https://api.github.com/repos/acme/widgets"), call.args)
        self.assertEqual(f"Bearer {TOKEN}", call.kwargs["headers"]["Authorization"])
        self.assertEqual("application/vnd.github+json", call.kwargs["headers"]["Accept"])
        self.assertEqual("2026-03-10", call.kwargs["headers"]["X-GitHub-Api-Version"])
        self.assertEqual((10, 12), call.kwargs["timeout"])
        self.assertTrue(call.kwargs["verify"])
        self.assertFalse(call.kwargs["allow_redirects"])
        self.assertFalse(api.session.trust_env)
        self.assertEqual(4999, meta["rate_limit"]["remaining"])
        self.assertEqual("SAFE-ID", meta["request_id"])

    def test_endpoint_and_credential_validation_blocks_ssrf_and_weak_tls(self):
        bad = [
            token_credential(base_url="http://api.github.com"),
            token_credential(base_url="https://user:pass@github.example/api/v3"),
            token_credential(base_url="https://127.0.0.1/api/v3", ghes_base_url_allowlist=["https://127.0.0.1/api/v3"]),
            token_credential(base_url="https://github.example/api/v3"),
            token_credential(base_url="https://github.example/not-api", ghes_base_url_allowlist=["https://github.example/not-api"]),
            token_credential(base_url="https://github.example:bad/api/v3", ghes_base_url_allowlist=["https://github.example:bad/api/v3"]),
        ]
        for credential in bad:
            with self.subTest(base_url=credential.get("base_url")), self.assertRaises(github.GitHubPackError):
                github.GitHubClient(credential)
        with self.assertRaisesRegex(github.GitHubPackError, "verify_tls must be true"):
            with github._tls_verify(token_credential(verify_tls=False)):
                pass
        with self.assertRaises(github.GitHubPackError):
            github.GitHubClient({"auth_type": "token", "token_kind": "fine_grained", "token": "bad\nheader"})

    def test_exact_allowlisted_ghes_origin_and_upload_origin(self):
        credential = token_credential(
            base_url="https://github.example.com/api/v3",
            ghes_base_url_allowlist=["https://github.example.com/api/v3"],
        )
        api = github.GitHubClient(credential)
        self.assertEqual("https://github.example.com/api/v3", api.base_url)
        self.assertEqual("https://github.example.com/api/uploads", api.upload_url)

    def test_app_installation_token_is_minted_once_without_retry(self):
        credential = {
            "auth_type": "app", "app_id": 10, "installation_id": 20,
            "private_key": "-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----",
        }
        api = github.GitHubClient(credential)
        api.session.request = mock.Mock(side_effect=[Response({"token": "INSTALLATION-TOKEN"}, 201), Response({"id": 1})])
        with mock.patch.object(api, "_app_jwt", return_value="APP-JWT"):
            api.request("GET", "/repos/acme/widgets")
        self.assertEqual(2, api.session.request.call_count)
        mint, request = api.session.request.call_args_list
        self.assertEqual("POST", mint.args[0])
        self.assertTrue(mint.args[1].endswith("/app/installations/20/access_tokens"))
        self.assertEqual("Bearer APP-JWT", mint.kwargs["headers"]["Authorization"])
        self.assertEqual("Bearer INSTALLATION-TOKEN", request.kwargs["headers"]["Authorization"])

    def test_link_pagination_is_bounded_and_cannot_leave_origin(self):
        api = client()
        api.session.request = mock.Mock(side_effect=[
            Response([{"id": 1}, {"id": 2}], headers={"Link": '<https://api.github.com/repos/acme/widgets/issues?page=2>; rel="next"'}),
            Response([{"id": 3}, {"id": 4}]),
        ])
        data, meta = api.request("GET", "/repos/acme/widgets/issues", query={"per_page": 2}, paginate=True, max_results=3)
        self.assertEqual([1, 2, 3], [item["id"] for item in data])
        self.assertEqual(2, meta["pages"])
        self.assertTrue(meta["truncated"])
        self.assertEqual(3, meta["result_count"])

        api.session.request = mock.Mock(return_value=Response([], headers={"Link": '<https://evil.invalid/steal>; rel="next"'}))
        with self.assertRaisesRegex(github.GitHubPackError, "pagination link"):
            api.request("GET", "/repos/acme/widgets/issues", paginate=True)

    def test_etag_not_modified_and_response_size_cap(self):
        api = client()
        api.session.request = mock.Mock(return_value=Response(raw=b"", status_code=304, headers={"ETag": '"two"'}))
        data, meta = api.request("GET", "/repos/acme/widgets", headers={"If-None-Match": '"one"'})
        self.assertEqual({"not_modified": True}, data)
        self.assertEqual('"two"', meta["etag"])
        self.assertEqual('"one"', api.session.request.call_args.kwargs["headers"]["If-None-Match"])
        api.session.request = mock.Mock(return_value=Response(raw=b"{}", headers={"Content-Length": str(github.MAX_RESPONSE_BYTES + 1)}))
        with self.assertRaisesRegex(github.GitHubPackError, "size limit"):
            api.request("GET", "/repos/acme/widgets")

    def test_only_safe_reads_retry(self):
        api = client()
        api.session.request = mock.Mock(side_effect=[Response({}, 503), Response({"ok": True})])
        with mock.patch("time.sleep"):
            data, _ = api.request("GET", "/repos/acme/widgets")
        self.assertTrue(data["ok"])
        self.assertEqual(2, api.session.request.call_count)

        api.session.request = mock.Mock(return_value=Response({"secret": TOKEN}, 503))
        with self.assertRaises(github.GitHubPackError) as caught:
            api.request("POST", "/repos/acme/widgets/issues", body={"body": TOKEN})
        self.assertEqual(1, api.session.request.call_count)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_transport_and_http_errors_are_redacted(self):
        api = client()
        api.session.request = mock.Mock(side_effect=requests.ConnectionError(f"leaked {TOKEN}"))
        with mock.patch("time.sleep"), self.assertRaises(github.GitHubPackError) as caught:
            api.request("GET", "/repos/acme/widgets")
        self.assertNotIn(TOKEN, str(caught.exception))
        api.session.request = mock.Mock(return_value=Response({"token": TOKEN}, 403, {
            "X-GitHub-Request-Id": "SAFE", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1786795200",
        }))
        api.read_retries = 0
        with self.assertRaises(github.GitHubPackError) as caught:
            api.request("GET", "/repos/acme/widgets")
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertIn("request_id=SAFE", str(caught.exception))
        self.assertIn("rate_remaining=0", str(caught.exception))


class OperationSafetyTests(unittest.TestCase):
    def test_repository_and_content_paths_cannot_cross_scope(self):
        api = client()
        for params in (
            {"owner": "acme/other", "repository": "widgets"},
            {"owner": "acme", "repository": "../other"},
        ):
            with self.subTest(params=params), self.assertRaises(github.GitHubPackError):
                github._execute(api, "repository_get", params)
        for path in ("../secret", "/absolute", "a//b", "a/./b"):
            with self.subTest(path=path), self.assertRaises(github.GitHubPackError):
                github._execute(api, "content_get", {"owner": "acme", "repository": "widgets", "path": path})

    def test_all_delete_and_label_replacement_confirmations_are_exact(self):
        api = client()
        api.session.request = mock.Mock(return_value=Response(raw=b"", status_code=204))
        with self.assertRaisesRegex(github.GitHubPackError, "DELETE_REPOSITORY"):
            github._execute(api, "repository_delete", {"owner": "acme", "repository": "widgets", "confirmation": "yes"})
        self.assertEqual(0, api.session.request.call_count)
        github._execute(api, "repository_delete", {
            "owner": "acme", "repository": "widgets", "confirmation": "DELETE_REPOSITORY:acme/widgets",
        })
        self.assertEqual("DELETE", api.session.request.call_args.args[0])

        api.session.request = mock.Mock(return_value=Response([]))
        with self.assertRaises(github.GitHubPackError):
            github._execute(api, "issue_labels_set", {
                "owner": "acme", "repository": "widgets", "issue_number": 4,
                "labels": ["z", "a"], "confirmation": "SET_ISSUE_LABELS:acme/widgets:4:z,a",
            })
        github._execute(api, "issue_labels_set", {
            "owner": "acme", "repository": "widgets", "issue_number": 4,
            "labels": ["z", "a"], "confirmation": "SET_ISSUE_LABELS:acme/widgets:4:a,z",
        })
        self.assertEqual("PUT", api.session.request.call_args.args[0])

    def test_merge_and_review_reject_head_races_and_merge_sends_sha(self):
        api = client()
        params = {
            "owner": "acme", "repository": "widgets", "pull_number": 7,
            "expected_head_sha": "abc123", "merge_method": "squash",
            "confirmation": "MERGE:acme/widgets:7:abc123:squash",
        }
        api.session.request = mock.Mock(return_value=Response({"head": {"sha": "changed"}}))
        with self.assertRaisesRegex(github.GitHubPackError, "head changed"):
            github._execute(api, "pull_merge", params)
        self.assertEqual(1, api.session.request.call_count)

        api.session.request = mock.Mock(side_effect=[Response({"head": {"sha": "abc123"}}), Response({"merged": True})])
        data, _ = github._execute(api, "pull_merge", params)
        self.assertTrue(data["merged"])
        merge_call = api.session.request.call_args_list[1]
        self.assertEqual("PUT", merge_call.args[0])
        self.assertEqual({"sha": "abc123", "merge_method": "squash"}, merge_call.kwargs["json"])

    def test_protection_replacement_requires_fresh_etag_complete_body_and_confirmation(self):
        api = client()
        params = {
            "owner": "acme", "repository": "widgets", "branch": "main", "expected_etag": '"p1"',
            "protection": {"required_status_checks": None},
            "confirmation": 'UPDATE_PROTECTION:acme/widgets:main:"p1"',
        }
        api.session.request = mock.Mock(return_value=Response({}, headers={"ETag": '"p1"'}))
        with self.assertRaisesRegex(github.GitHubPackError, "all replacement fields"):
            github._execute(api, "protection_update", params)
        self.assertEqual(1, api.session.request.call_count)

        params["protection"] = {
            "required_status_checks": None, "enforce_admins": True,
            "required_pull_request_reviews": None, "restrictions": None,
        }
        api.session.request = mock.Mock(side_effect=[Response({}, headers={"ETag": '"p1"'}), Response({"url": "safe"})])
        github._execute(api, "protection_update", params)
        put = api.session.request.call_args_list[1]
        self.assertEqual("PUT", put.args[0])
        self.assertEqual('"p1"', put.kwargs["headers"]["If-Match"])

        api.session.request = mock.Mock(return_value=Response({}, headers={"ETag": '"p2"'}))
        with self.assertRaisesRegex(github.GitHubPackError, "ETag changed"):
            github._execute(api, "protection_update", params)

    def test_team_and_deployment_mutations_are_current_scoped_and_confirmed(self):
        api = client()
        api.session.request = mock.Mock(return_value=Response({"state": "active"}))
        params = {
            "organization": "acme", "team_slug": "ops", "username": "alice", "role": "maintainer",
            "confirmation": "ADD_TEAM_MEMBER:acme:ops:alice:maintainer",
        }
        github._execute(api, "team_member_add", params)
        call = api.session.request.call_args
        self.assertEqual("PUT", call.args[0])
        self.assertEqual("https://api.github.com/orgs/acme/teams/ops/memberships/alice", call.args[1])

        deploy = {
            "owner": "acme", "repository": "widgets", "ref": "abc123", "environment": "prod",
            "required_contexts": [], "confirmation": "wrong",
        }
        api.session.request.reset_mock()
        with self.assertRaises(github.GitHubPackError):
            github._execute(api, "deployment_create", deploy)
        self.assertEqual(0, api.session.request.call_count)
        deploy["confirmation"] = "CREATE_DEPLOYMENT:acme/widgets:abc123:prod"
        github._execute(api, "deployment_create", deploy)
        self.assertFalse(api.session.request.call_args.kwargs["json"]["auto_merge"])

    def test_webhook_creation_is_allowlisted_key_secret_only_and_confirmed(self):
        api = client(webhook_host_allowlist=["attune.example.com"], webhook_secret="A" * 32)
        api.session.request = mock.Mock(return_value=Response({"id": 12}, 201))
        params = {
            "owner": "acme", "repository": "widgets", "webhook_url": "https://attune.example.com/github",
            "events": ["push", "issues"], "confirmation": "CREATE_WEBHOOK:acme/widgets:attune.example.com:issues,push",
        }
        github._execute(api, "webhook_create", params)
        body = api.session.request.call_args.kwargs["json"]
        self.assertEqual("A" * 32, body["config"]["secret"])
        self.assertEqual("0", body["config"]["insecure_ssl"])
        self.assertNotIn("secret", params)

        for url in ("http://attune.example.com/github", "https://evil.invalid/github", "https://attune.example.com/github?token=x"):
            params["webhook_url"] = url
            with self.subTest(url=url), self.assertRaises(github.GitHubPackError):
                github._execute(api, "webhook_create", params)

    def test_artifact_download_is_confined_new_private_and_strips_redirect_auth(self):
        api = client()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "downloads").mkdir()
            api.session.request = mock.Mock(side_effect=[
                Response(raw=b"", status_code=302, headers={"Location": "https://objects.githubusercontent.com/signed"}),
                Response(raw=b"zip bytes", headers={"Content-Length": "9"}),
            ])
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}):
                data, _ = github._execute(api, "artifact_download", {
                    "owner": "acme", "repository": "widgets", "artifact_id": 5,
                    "artifact_path": "downloads/run.zip", "max_download_bytes": 100,
                })
            target = root / "downloads" / "run.zip"
            self.assertEqual(b"zip bytes", target.read_bytes())
            self.assertEqual(0o600, target.stat().st_mode & 0o777)
            self.assertEqual(9, data["bytes"])
            redirected = api.session.request.call_args_list[1]
            self.assertNotIn("Authorization", redirected.kwargs["headers"])
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}), self.assertRaisesRegex(github.GitHubPackError, "must not already exist"):
                github._artifact_path({"artifact_path": "downloads/run.zip"}, existing=False)
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}), self.assertRaises(github.GitHubPackError):
                github._artifact_path({"artifact_path": "../escape"}, existing=False)

    def test_artifact_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "link").symlink_to(outside, target_is_directory=True)
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}), self.assertRaisesRegex(github.GitHubPackError, "symlinks"):
                github._artifact_path({"artifact_path": "link/file.zip"}, existing=False)


class KeyAndEntryPointTests(unittest.TestCase):
    def test_fetch_key_accepts_json_and_hides_lookup_exceptions(self):
        parsed = types.SimpleNamespace(data=types.SimpleNamespace(value='{"auth_type":"token","token_kind":"fine_grained","token":"secret"}'))
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=mock.Mock(return_value=types.SimpleNamespace(status_code=200, parsed=parsed)))
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual("fine_grained", github._fetch_key("github.credentials")["token_kind"])
        with mock.patch.dict(sys.modules, {"attune": None}):
            with self.assertRaises(github.GitHubPackError) as caught:
                github._fetch_key("github.credentials")
        self.assertNotIn("secret", str(caught.exception).lower())

    def test_entry_point_never_echoes_parameters_or_unknown_errors(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("github_action_test", ROOT / "actions" / "github_action.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for raw, error in (("[]", None), ('{"body":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))):
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(module, "execute_action", side_effect=error) if error else mock.patch.object(module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "github.issue_create"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
