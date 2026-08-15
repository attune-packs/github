# GitHub Hosting Platform Attune Pack

This pack adapts the Apache-2.0 StackStorm Exchange GitHub pack `v2.1.5` at
revision `fc8e45bd25bcfdd891f3e88e0b87f7592fe7f634`. It provides 67 explicit
hosting-platform actions over one direct GitHub REST client. It deliberately
complements the separate `git` pack: local working trees, remotes, diffs,
commits, tags, fetch, and push belong there; GitHub repositories, collaboration,
releases, deployments, Actions, teams, and hooks belong here.

All API requests send:

- `Accept: application/vnd.github+json`
- `X-GitHub-Api-Version: 2026-03-10`
- a pack-specific `User-Agent`

[SOURCE.md](SOURCE.md) records the exact upstream and current API verification.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- Network access to `https://api.github.com`, or to a reviewed GHES API origin.
- An encrypted, pack-owned Attune Key, normally `github.credentials`.
- GitHub permissions scoped to the specific actions, owners, and repositories.
- `ATTUNE_ARTIFACTS_DIR` for release-asset and Actions-artifact transfers.

## Authentication Preference

Use authentication in this order:

1. **GitHub App installation token (preferred).** Installation access tokens are
   short lived and can be scoped to selected repositories and permissions. The
   pack signs a nine-minute App JWT, requests an installation token once per
   action execution, and never returns either token.
2. **Fine-grained personal access token.** Restrict the owner, repositories,
   permissions, and expiration. This is the preferred human-token fallback.
3. **Classic personal access token.** Use only for a documented compatibility
   gap, with the minimum scopes and a rotation plan. Classic tokens are broader
   and are not preferred for new deployments.

GitHub App Key:

```json
{
  "auth_type": "app",
  "app_id": 12345,
  "installation_id": 67890,
  "private_key": "-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----",
  "verify_tls": true
}
```

Fine-grained token Key:

```json
{
  "auth_type": "token",
  "token_kind": "fine_grained",
  "token": "REDACTED",
  "verify_tls": true
}
```

For a classic token, set `token_kind` to `classic`. Action parameters contain
only a Key reference. Tokens, App private keys, and webhook secrets never appear
in action contracts.

GitHub permissions are endpoint-specific. Typical fine-grained/App repository
permissions include Administration, Actions, Contents, Deployments, Issues,
Metadata, Pull requests, and Webhooks; organization team operations also need
Members permission. Grant only read or write access required by deployed
actions. GitHub returns `403` or `404` when the token cannot see a resource.

## GitHub Enterprise Server

GitHub.com uses only the fixed `https://api.github.com` and
`https://uploads.github.com` endpoints. GHES requires an exact API URL ending in
`/api/v3`, and that exact normalized URL must also appear in the Key's
`ghes_base_url_allowlist`:

```json
{
  "auth_type": "app",
  "app_id": 12345,
  "installation_id": 67890,
  "private_key": "-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----",
  "base_url": "https://github.example.com/api/v3",
  "ghes_base_url_allowlist": ["https://github.example.com/api/v3"],
  "verify_tls": true,
  "ca_cert": "-----BEGIN CERTIFICATE-----\nREDACTED CA\n-----END CERTIFICATE-----"
}
```

URLs with credentials, query strings, fragments, IP-literal hosts, non-HTTPS
schemes, arbitrary paths, or non-allowlisted GHES origins are rejected. TLS
verification is mandatory. An optional private CA is written mode `0600` in a
private temporary directory and removed after execution. Redirects are disabled
for API calls. Download redirects are followed once without authorization only
to HTTPS GitHub asset domains, the configured GHES host, or exact hosts in the
Key's `download_host_allowlist`. Environment proxy variables are ignored so
credentials go only to the validated endpoint.

The selected GHES release must support REST API version `2026-03-10` and the
used endpoints. Older GHES compatibility is a live deployment check, not an
automatic API-version downgrade.

## Actions

Repository actions: `repository_get`, `repository_list`, `repository_create`,
`repository_update`, `repository_delete`.

Issue collaboration actions: `issue_get`, `issue_list`, `issue_create`,
`issue_update`, `comment_list`, `comment_create`, `comment_update`,
`comment_delete`, `label_list`, `label_create`, `label_delete`,
`issue_labels_set`.

Pull request actions: `pull_get`, `pull_list`, `pull_create`, `pull_update`,
`pull_review_list`, `pull_review_create`, `pull_merge`.

Branch and protection actions: `branch_list`, `branch_create`, `branch_delete`,
`protection_get`, `protection_update`, `protection_delete`.

Content, commit, and status actions: `content_get`, `content_put`,
`content_delete`, `commit_list`, `commit_get`, `commit_status_list`,
`commit_status_create`.

Release and asset actions: `release_list`, `release_get`, `release_create`,
`release_update`, `release_delete`, `release_asset_list`,
`release_asset_upload`, `release_asset_download`, `release_asset_delete`.

Deployment actions: `deployment_list`, `deployment_create`,
`deployment_status_list`, `deployment_status_create`.

GitHub Actions operations: `workflow_list`, `workflow_get`,
`workflow_dispatch`, `workflow_run_list`, `workflow_run_get`,
`workflow_run_control`, `artifact_list`, `artifact_download`, `artifact_delete`.

Current organization-team operations: `team_list`, `team_get`,
`team_member_list`, `team_member_add`, `team_member_remove`.

Repository webhook administration: `webhook_list`, `webhook_create`,
`webhook_delete`.

Every action accepts one flat top-level JSON parameter object on stdin and
returns:

```json
{
  "operation": "issue_list",
  "data": [],
  "meta": {
    "status_code": 200,
    "etag": "W/\"example\"",
    "request_id": "EXAMPLE:1",
    "rate_limit": {
      "limit": 5000,
      "remaining": 4999,
      "used": 1,
      "reset_at": "2026-08-15T12:00:00+00:00",
      "resource": "core",
      "retry_after_seconds": null
    },
    "pages": 1,
    "result_count": 0,
    "truncated": false
  }
}
```

## Safety Model

Owner and repository are mandatory on repository-scoped actions. Organization,
team slug, numeric IDs, branch, expected SHA, and expected ETag are separate
parameters; no action accepts an arbitrary URL, route, method, headers, token,
or generic API body. User-owned repository creation verifies the authenticated
login before mutating `/user/repos`.

List actions follow only RFC-style `Link` entries marked `rel="next"`, require
the next URL to stay under the configured API base, use `per_page <= 100`, and
stop at `max_results <= 1000`. `meta.truncated` reports a cap stop. JSON responses
are capped at 16 MiB.

GET/HEAD requests may retry zero to two times for transport errors, `429`,
`502`, `503`, `504`, or primary rate-limit `403`. Delays are capped at five
seconds. POST, PUT, PATCH, and DELETE are attempted exactly once, including App
token creation; mutation ambiguity is returned to the caller rather than
silently duplicated. HTTP errors report only status, request ID, and safe
rate-limit fields, never response bodies, request bodies, URLs, or library error
text.

Read actions accept `etag` and return `{ "not_modified": true }` on `304`.
Selected updates accept `expected_etag`. Pull review and merge first verify the
current head and send that exact SHA; merge confirmation includes it. Content
updates use GitHub's blob SHA. Branch protection is a replacement API:
`protection_update` requires all four required top-level replacement fields, a
freshly checked ETag, `If-Match`, and confirmation. It never derives a partial
body from the GET response, which has a different shape.

GitHub's branch-protection documentation does not promise conditional `If-Match`
semantics. The preflight ETag check detects already-stale input, but an
administrator can still change protection between that read and the one-shot
`PUT`. Run protection replacement only during a controlled change window and
verify the returned policy. Deployment creation similarly requires callers to
provide `required_contexts` explicitly; `[]` is accepted only as an intentional
choice to bypass status-context checks.

All deletes require an exact case-sensitive confirmation. Merge, protection,
team membership, deployments/statuses, workflow dispatch/control, issue-label
replacement, release publication/update, and webhook creation are also
confirmed. Each action YAML documents its exact form. Confirmations are a human
target check, not an authorization mechanism.

## Assets

Uploads accept only an existing regular, non-symlink file beneath the resolved
`ATTUNE_ARTIFACTS_DIR`. Downloads require an existing confined parent directory,
create a new mode-`0600` file with exclusive/no-follow semantics, enforce
`max_download_bytes`, delete partial files on failure, and return byte count and
SHA-256. Existing files are never overwritten. Archive extraction is outside
this pack, so ZIP path traversal cannot occur inside the downloader.

`content_get` returns GitHub's content object, which can include base64 file
contents. Execution-result access must therefore be at least as restricted as
repository Contents read access.

## Repository Webhooks and Event Gap

Webhook creation requires all of the following:

- an exact destination hostname in Key field `webhook_host_allowlist`;
- HTTPS on the default port, with no URL credentials, query, or fragment;
- a Key-owned `webhook_secret` of at least 16 characters;
- JSON content, TLS verification at the GitHub delivery side, explicit events,
  and exact repository/host/sorted-events confirmation.

Example additional Key fields:

```json
{
  "webhook_host_allowlist": ["attune.example.com"],
  "webhook_secret": "REDACTED_RANDOM_WEBHOOK_SECRET"
}
```

No Attune sensor or trigger is included. Attune currently verifies GitHub's
`X-Hub-Signature-256`, but its webhook receiver does not persist and reject
duplicate `X-GitHub-Delivery` IDs and has no bounded replay window. That fails
this pack's replay/delivery-ID deduplication requirement. Event ingestion is
deferred until Attune can atomically deduplicate authenticated delivery IDs
before event creation. The upstream polling sensor is not a secure substitute:
it can miss capped history and its local cursor is not webhook delivery dedupe.

## Validation

```bash
python3 -m unittest discover -s /home/david/Codebase/attune-packs/github/tests -v
attune --output json pack check /home/david/Codebase/attune-packs/github
attune pack test /home/david/Codebase/attune-packs/github --detailed
```

Tests mock all GitHub and Attune Key calls and require no GitHub credentials.
Live validation remains deployment-specific because App installations, token
permissions, repository rules, branch policies, GHES versions/PKI, organization
roles, Actions settings, rate limits, and artifact storage differ by site.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and prominent modification details are in [NOTICE](NOTICE).
