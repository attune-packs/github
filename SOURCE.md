# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-github
- Upstream version: `2.1.5` (tag `v2.1.5`)
- Verified revision: `fc8e45bd25bcfdd891f3e88e0b87f7592fe7f634`
- Revision date: `2023-09-15T14:43:34Z`
- Revision signature: verified by GitHub (`valid`; verified at `2024-11-13T07:17:41Z`)
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision
- API baseline reviewed: GitHub REST API documentation and `/versions` on `2026-08-15`
- API version used: `2026-03-10`
- Other API version reported as supported: `2022-11-28`

The source revision is both the upstream default-branch head and the commit
target of tag `v2.1.5`. The upstream `pack.yaml` declares version `2.1.5`.
GitHub's repository metadata reports SPDX `Apache-2.0`, matching the included
license file.

Authoritative API references:

- https://api.github.com/versions
- https://docs.github.com/en/rest/about-the-rest-api/api-versions
- https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app
- https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
- https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- https://docs.github.com/en/rest/repos
- https://docs.github.com/en/rest/issues
- https://docs.github.com/en/rest/pulls
- https://docs.github.com/en/rest/branches/branch-protection
- https://docs.github.com/en/rest/repos/contents
- https://docs.github.com/en/rest/releases
- https://docs.github.com/en/rest/deployments
- https://docs.github.com/en/rest/actions
- https://docs.github.com/en/rest/teams
- https://docs.github.com/en/rest/webhooks/repos
- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

The upstream pack used PyGithub, accepted a broad global token, disabled TLS
verification in a direct request helper, scraped authenticated HTML for some
statistics, and polled repository events without durable cross-process replay
protection. This adaptation retains the useful hosting-platform intent but uses
one explicit direct REST client, current routes, scoped Attune Keys, strict TLS,
fixed or exact-allowlisted API endpoints, bounded pagination, ETags, safe read
retry, exact destructive confirmations, and secret-safe failures. HTML scraping,
password login, token storage, event polling, and arbitrary request dispatch are
not translated.
