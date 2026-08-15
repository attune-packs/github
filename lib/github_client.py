"""Bounded, direct GitHub REST API client and explicit action dispatcher."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, urlencode, urlsplit

import requests


API_VERSION = "2026-03-10"
DEFAULT_CREDENTIAL_KEY = "github.credentials"
GITHUB_API_URL = "https://api.github.com"
GITHUB_UPLOAD_URL = "https://uploads.github.com"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RESULTS_LIMIT = 1000
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024
_HEX_COLOR = re.compile(r"^[0-9A-Fa-f]{6}$")
_SAFE_DOWNLOAD_SUFFIXES = (".githubusercontent.com", ".github.com")


class GitHubPackError(Exception):
    """Action-safe error that never includes request bodies or credentials."""


def _fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise GitHubPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:
        raise GitHubPackError(f"could not read GitHub credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise GitHubPackError("GitHub credential Key was not found")
        raise GitHubPackError(f"could not read GitHub credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise GitHubPackError("GitHub credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise GitHubPackError("GitHub credential Key must contain an object")
    return value


def _string(params: dict[str, Any], name: str, *, optional: bool = False) -> str | None:
    value = params.get(name)
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise GitHubPackError(f"{name} must be a non-empty string without control characters")
    return value


def _integer(
    params: dict[str, Any], name: str, default: int | None, minimum: int, maximum: int
) -> int | None:
    value = params.get(name, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise GitHubPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise GitHubPackError(f"{name} must be a boolean")
    return value


def _list(params: dict[str, Any], name: str, *, strings: bool = True, default: Any = None) -> list[Any]:
    value = params.get(name, default)
    if not isinstance(value, list):
        raise GitHubPackError(f"{name} must be an array")
    if strings and any(not isinstance(item, str) or not item for item in value):
        raise GitHubPackError(f"{name} must contain only non-empty strings")
    return value


def _object(params: dict[str, Any], name: str) -> dict[str, Any]:
    value = params.get(name)
    if not isinstance(value, dict):
        raise GitHubPackError(f"{name} must be an object")
    return value


def _segment(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or "/" in value:
        raise GitHubPackError(f"{name} must be one non-empty path segment")
    if any(ord(char) < 32 for char in value):
        raise GitHubPackError(f"{name} contains a control character")
    return quote(value, safe="")


def _content_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise GitHubPackError("path must be a non-empty relative repository path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise GitHubPackError("path contains an empty, '.' or '..' segment")
    return "/".join(quote(part, safe="") for part in parts)


def _repo(params: dict[str, Any]) -> tuple[str, str, str]:
    owner_raw = _string(params, "owner")
    repo_raw = _string(params, "repository")
    owner = _segment(owner_raw, "owner")
    repository = _segment(repo_raw, "repository")
    return owner, repository, f"{owner_raw}/{repo_raw}"


def _confirm(params: dict[str, Any], expected: str) -> None:
    if params.get("confirmation") != expected:
        raise GitHubPackError(f"confirmation must exactly equal {expected}")


def _enum(params: dict[str, Any], name: str, choices: set[str], default: str | None = None) -> str:
    value = params.get(name, default)
    if value not in choices:
        raise GitHubPackError(f"{name} must be one of: {', '.join(sorted(choices))}")
    return value


def _optional_body(params: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {name: params[name] for name in names if name in params and params[name] is not None}


def _pagination(params: dict[str, Any]) -> tuple[int, int]:
    per_page = _integer(params, "per_page", 100, 1, 100)
    max_results = _integer(params, "max_results", 500, 1, MAX_RESULTS_LIMIT)
    return int(per_page or 100), int(max_results or 500)


def _rate_metadata(response: requests.Response) -> dict[str, Any]:
    headers = response.headers
    reset = headers.get("X-RateLimit-Reset")
    reset_at = None
    if reset and reset.isdigit():
        try:
            reset_at = datetime.fromtimestamp(int(reset), tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            pass

    def number(name: str) -> int | None:
        value = headers.get(name)
        return int(value) if value and value.isdigit() else None

    return {
        "limit": number("X-RateLimit-Limit"),
        "remaining": number("X-RateLimit-Remaining"),
        "used": number("X-RateLimit-Used"),
        "reset_at": reset_at,
        "resource": headers.get("X-RateLimit-Resource"),
        "retry_after_seconds": number("Retry-After"),
    }


def _response_bytes(response: requests.Response, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length and content_length.isdigit() and int(content_length) > limit:
        raise GitHubPackError("GitHub response exceeded the configured size limit")
    chunks: list[bytes] = []
    size = 0
    if hasattr(response, "iter_content"):
        iterator = response.iter_content(chunk_size=64 * 1024)
    else:
        iterator = [response.content]
    for chunk in iterator:
        if not chunk:
            continue
        size += len(chunk)
        if size > limit:
            raise GitHubPackError("GitHub response exceeded the configured size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_link(value: str | None) -> str | None:
    if not value:
        return None
    for item in value.split(","):
        parts = [part.strip() for part in item.split(";")]
        if len(parts) >= 2 and 'rel="next"' in parts[1:] and parts[0].startswith("<") and parts[0].endswith(">"):
            return parts[0][1:-1]
    return None


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@contextmanager
def _tls_verify(credential: dict[str, Any]) -> Iterator[bool | str]:
    verify_tls = credential.get("verify_tls", True)
    if verify_tls is not True:
        raise GitHubPackError("verify_tls must be true")
    ca_cert = credential.get("ca_cert")
    if ca_cert is None:
        yield True
        return
    if not isinstance(ca_cert, str) or not ca_cert.strip():
        raise GitHubPackError("ca_cert must be a non-empty PEM string")
    with tempfile.TemporaryDirectory(prefix="attune-github-") as directory:
        path = Path(directory, "ca.pem")
        path.write_text(ca_cert, encoding="utf-8")
        os.chmod(path, 0o600)
        yield str(path)


class GitHubClient:
    """One direct client for all GitHub API calls in an action execution."""

    def __init__(
        self,
        credential: dict[str, Any],
        timeout_seconds: int = 30,
        read_retries: int = 1,
        verify: bool | str = True,
        session: requests.Session | None = None,
    ):
        if not isinstance(credential, dict):
            raise GitHubPackError("credential must be an object")
        base_url = credential.get("base_url", GITHUB_API_URL)
        if not isinstance(base_url, str):
            raise GitHubPackError("credential base_url must be a string")
        self.base_url, self.upload_url, self.allowed_api_origin = self._validate_base_url(base_url, credential)
        auth_type = credential.get("auth_type")
        if auth_type not in {"app", "token"}:
            raise GitHubPackError("credential auth_type must be 'app' or 'token'")
        self.auth_type = auth_type
        if auth_type == "token":
            token = credential.get("token")
            token_kind = credential.get("token_kind")
            if token_kind not in {"fine_grained", "classic"}:
                raise GitHubPackError("token credentials require token_kind 'fine_grained' or 'classic'")
            if not isinstance(token, str) or not token or any(ord(char) < 32 for char in token):
                raise GitHubPackError("credential token must be a non-empty string without control characters")
            self._access_token = token
        else:
            app_id = credential.get("app_id")
            installation_id = credential.get("installation_id")
            private_key = credential.get("private_key")
            if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id < 1:
                raise GitHubPackError("app_id must be a positive integer")
            if isinstance(installation_id, bool) or not isinstance(installation_id, int) or installation_id < 1:
                raise GitHubPackError("installation_id must be a positive integer")
            if not isinstance(private_key, str) or "PRIVATE KEY" not in private_key:
                raise GitHubPackError("private_key must be a PEM private key")
            self.app_id = app_id
            self.installation_id = installation_id
            self.private_key = private_key
            self._access_token = None
        self.credential = credential
        self.timeout_seconds = timeout_seconds
        self.read_retries = read_retries
        self.verify = verify
        self.session = session or requests.Session()
        self.session.trust_env = False

    @staticmethod
    def _validate_base_url(base_url: str, credential: dict[str, Any]) -> tuple[str, str, str]:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise GitHubPackError("credential base_url must be an HTTPS API URL without credentials, query or fragment")
        try:
            port = parsed.port
        except ValueError:
            raise GitHubPackError("credential base_url has an invalid port") from None
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise GitHubPackError("credential base_url must use an allowlisted DNS hostname, not an IP literal")
        normalized = base_url.rstrip("/")
        if normalized == GITHUB_API_URL:
            if port not in {None, 443} or parsed.path not in {"", "/"}:
                raise GitHubPackError("GitHub.com API endpoint must be exactly https://api.github.com")
            return GITHUB_API_URL, GITHUB_UPLOAD_URL, GITHUB_API_URL
        allowlist = credential.get("ghes_base_url_allowlist", [])
        if not isinstance(allowlist, list) or any(not isinstance(item, str) for item in allowlist):
            raise GitHubPackError("ghes_base_url_allowlist must be an array of exact HTTPS API URLs")
        if normalized not in {item.rstrip("/") for item in allowlist}:
            raise GitHubPackError("GHES base_url is not in credential ghes_base_url_allowlist")
        if parsed.path.rstrip("/") != "/api/v3" or parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
            raise GitHubPackError("GHES base_url must be an allowlisted https://HOST[:PORT]/api/v3 URL")
        origin = f"https://{parsed.hostname}" + (f":{port}" if port and port != 443 else "")
        return normalized, origin + "/api/uploads", origin

    def _app_jwt(self) -> str:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except Exception as exc:
            raise GitHubPackError(f"GitHub App signing dependency is unavailable ({type(exc).__name__})") from None
        now = int(time.time())
        header = _base64url(b'{"alg":"RS256","typ":"JWT"}')
        payload = _base64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(self.app_id)}, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        try:
            key = serialization.load_pem_private_key(self.private_key.encode(), password=None)
            signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception as exc:
            raise GitHubPackError(f"could not sign GitHub App JWT ({type(exc).__name__})") from None
        return f"{header}.{payload}.{_base64url(signature)}"

    def _mint_installation_token(self) -> str:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._app_jwt()}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "attune-github-pack/0.1.0",
        }
        try:
            response = self.session.request(
                "POST",
                f"{self.base_url}/app/installations/{self.installation_id}/access_tokens",
                headers=headers,
                timeout=(min(10, self.timeout_seconds), self.timeout_seconds),
                verify=self.verify,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise GitHubPackError(f"GitHub App token request failed ({type(exc).__name__})") from None
        try:
            raw = _response_bytes(response)
            if not 200 <= response.status_code < 300:
                raise GitHubPackError(self._http_error(response))
            try:
                data = json.loads(raw) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise GitHubPackError("GitHub App token response was not valid JSON") from None
            token = data.get("token") if isinstance(data, dict) else None
            if not isinstance(token, str) or not token:
                raise GitHubPackError("GitHub App token response did not contain a token")
            return token
        finally:
            response.close()

    def _token(self) -> str:
        if self._access_token is None:
            self._access_token = self._mint_installation_token()
        return self._access_token

    def _headers(self, extra: dict[str, str] | None = None, *, authenticated: bool = True) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "attune-github-pack/0.1.0",
        }
        if authenticated:
            headers["Authorization"] = f"Bearer {self._token()}"
        if extra:
            headers.update(extra)
        return headers

    def _http_error(self, response: requests.Response) -> str:
        request_id = response.headers.get("X-GitHub-Request-Id")
        rate = _rate_metadata(response)
        details = []
        if request_id:
            details.append(f"request_id={request_id}")
        if rate["remaining"] is not None:
            details.append(f"rate_remaining={rate['remaining']}")
        if rate["reset_at"]:
            details.append(f"rate_reset_at={rate['reset_at']}")
        suffix = f" ({', '.join(details)})" if details else ""
        return f"GitHub returned HTTP {response.status_code}{suffix}"

    def _validate_next_url(self, url: str) -> str:
        parsed = urlsplit(url)
        base = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or parsed.netloc.lower() != base.netloc.lower()
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not parsed.path.startswith(base.path.rstrip("/") + "/")
        ):
            raise GitHubPackError("GitHub pagination link left the configured API endpoint")
        return url

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        query: dict[str, Any] | None,
        body: Any,
        data: Any,
        headers: dict[str, str] | None,
    ) -> requests.Response:
        try:
            return self.session.request(
                method,
                url,
                params=query,
                json=body,
                data=data,
                headers=self._headers(headers),
                timeout=(min(10, self.timeout_seconds), self.timeout_seconds),
                verify=self.verify,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise GitHubPackError(f"GitHub request failed ({type(exc).__name__})") from None

    def _send(
        self,
        method: str,
        url: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[Any, dict[str, Any], str | None]:
        attempts = self.read_retries + 1 if method in {"GET", "HEAD"} else 1
        response = None
        for attempt in range(attempts):
            try:
                response = self._request_once(method, url, query=query, body=body, data=data, headers=headers)
            except GitHubPackError:
                if attempt + 1 >= attempts:
                    raise
                time.sleep(min(0.25 * (2**attempt), 1.0))
                continue
            retryable = response.status_code in {429, 502, 503, 504} or (
                response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0"
            )
            if retryable and attempt + 1 < attempts:
                retry_after = response.headers.get("Retry-After", "")
                delay = int(retry_after) if retry_after.isdigit() else min(0.25 * (2**attempt), 1.0)
                response.close()
                time.sleep(min(delay, 5))
                continue
            break
        assert response is not None
        try:
            meta = {
                "status_code": response.status_code,
                "etag": response.headers.get("ETag"),
                "request_id": response.headers.get("X-GitHub-Request-Id"),
                "rate_limit": _rate_metadata(response),
            }
            if response.status_code == 304:
                return {"not_modified": True}, meta, None
            raw = _response_bytes(response)
            if not 200 <= response.status_code < 300:
                raise GitHubPackError(self._http_error(response))
            if not raw:
                data_value: Any = {"success": True}
            else:
                try:
                    data_value = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise GitHubPackError("GitHub returned an invalid JSON response") from None
            return data_value, meta, _parse_link(response.headers.get("Link"))
        finally:
            response.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        paginate: bool = False,
        collection_key: str | None = None,
        max_results: int = 500,
    ) -> tuple[Any, dict[str, Any]]:
        url = self.base_url + path
        if not paginate:
            result, meta, _ = self._send(method, url, query=query, body=body, data=data, headers=headers)
            meta.update({"pages": 1, "result_count": len(result) if isinstance(result, list) else None, "truncated": False})
            return result, meta
        results: list[Any] = []
        pages = 0
        truncated = False
        final_meta: dict[str, Any] = {}
        while url:
            value, final_meta, next_url = self._send("GET", url, query=query if pages == 0 else None, headers=headers)
            pages += 1
            if collection_key:
                if not isinstance(value, dict) or not isinstance(value.get(collection_key), list):
                    raise GitHubPackError(f"GitHub response did not contain expected {collection_key} collection")
                items = value[collection_key]
            elif isinstance(value, list):
                items = value
            else:
                raise GitHubPackError("GitHub list response was not an array")
            room = max_results - len(results)
            results.extend(items[:room])
            if len(items) > room or (len(results) >= max_results and next_url):
                truncated = True
                break
            url = self._validate_next_url(next_url) if next_url else ""
        final_meta.update({"pages": pages, "result_count": len(results), "truncated": truncated})
        return results, final_meta

    def upload_asset(
        self, owner: str, repository: str, release_id: int, name: str, content_type: str, source: Path
    ) -> tuple[Any, dict[str, Any]]:
        query = urlencode({"name": name})
        url = f"{self.upload_url}/repos/{owner}/{repository}/releases/{release_id}/assets?{query}"
        headers = {"Accept": "application/vnd.github+json", "Content-Type": content_type, "Content-Length": str(source.stat().st_size)}
        with source.open("rb") as handle:
            result, meta, _ = self._send("POST", url, data=handle, headers=headers)
        meta.update({"pages": 1, "result_count": None, "truncated": False})
        return result, meta

    def download(self, path: str, destination: Path, max_bytes: int) -> tuple[dict[str, Any], dict[str, Any]]:
        url = self.base_url + path
        response = self._request_once("GET", url, query=None, body=None, data=None, headers={"Accept": "application/octet-stream"})
        authenticated = True
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise GitHubPackError("GitHub download redirect omitted Location")
            parsed = urlsplit(location)
            host = (parsed.hostname or "").lower()
            try:
                redirect_port = parsed.port
            except ValueError:
                raise GitHubPackError("GitHub download redirect has an invalid port") from None
            api_origin = urlsplit(self.allowed_api_origin)
            api_port = api_origin.port or 443
            same_origin_host = host == api_origin.hostname and (redirect_port or 443) == api_port
            github_asset_host = any(host.endswith(suffix) for suffix in _SAFE_DOWNLOAD_SUFFIXES) and redirect_port in {None, 443}
            extra_hosts = self.credential.get("download_host_allowlist", [])
            extra_host = isinstance(extra_hosts, list) and host in {item.lower() for item in extra_hosts if isinstance(item, str)} and redirect_port in {None, 443}
            allowed = same_origin_host or github_asset_host or extra_host
            if parsed.scheme != "https" or not allowed or parsed.username or parsed.password or parsed.fragment:
                raise GitHubPackError("GitHub download redirect left the HTTPS download allowlist")
            try:
                response = self.session.request(
                    "GET",
                    location,
                    headers={"User-Agent": "attune-github-pack/0.1.0"},
                    timeout=(min(10, self.timeout_seconds), self.timeout_seconds),
                    verify=self.verify,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException as exc:
                raise GitHubPackError(f"GitHub download failed ({type(exc).__name__})") from None
            authenticated = False
        try:
            if not 200 <= response.status_code < 300:
                raise GitHubPackError(self._http_error(response) if authenticated else f"GitHub download returned HTTP {response.status_code}")
            content_length = response.headers.get("Content-Length")
            if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                raise GitHubPackError("GitHub download exceeds max_download_bytes")
            digest = hashlib.sha256()
            size = 0
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(destination, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        size += len(chunk)
                        if size > max_bytes:
                            raise GitHubPackError("GitHub download exceeds max_download_bytes")
                        digest.update(chunk)
                        output.write(chunk)
            except Exception:
                destination.unlink(missing_ok=True)
                raise
            meta = {
                "status_code": response.status_code,
                "etag": response.headers.get("ETag"),
                "request_id": response.headers.get("X-GitHub-Request-Id") if authenticated else None,
                "rate_limit": _rate_metadata(response) if authenticated else {},
                "pages": 1,
                "result_count": None,
                "truncated": False,
            }
            return {"artifact_path": str(destination), "bytes": size, "sha256": digest.hexdigest()}, meta
        finally:
            response.close()


def _query_with_pagination(params: dict[str, Any], names: tuple[str, ...]) -> tuple[dict[str, Any], int]:
    per_page, max_results = _pagination(params)
    query = {name: params[name] for name in names if name in params and params[name] is not None and params[name] != ""}
    query["per_page"] = per_page
    return query, max_results


def _etag_headers(params: dict[str, Any], name: str = "etag") -> dict[str, str]:
    value = _string(params, name, optional=True)
    return {"If-None-Match" if name == "etag" else "If-Match": value} if value else {}


def _artifact_root() -> Path:
    raw = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not raw:
        raise GitHubPackError("ATTUNE_ARTIFACTS_DIR is required for asset operations")
    root = Path(raw)
    if not root.is_absolute():
        raise GitHubPackError("ATTUNE_ARTIFACTS_DIR must be absolute")
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        raise GitHubPackError("ATTUNE_ARTIFACTS_DIR is unavailable") from None
    if not resolved.is_dir():
        raise GitHubPackError("ATTUNE_ARTIFACTS_DIR must be a directory")
    return resolved


def _artifact_path(params: dict[str, Any], *, existing: bool) -> Path:
    root = _artifact_root()
    raw = _string(params, "artifact_path")
    candidate = Path(raw)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise GitHubPackError("artifact_path must be a normalized relative path")
    path = root.joinpath(candidate)
    current = root
    for part in candidate.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise GitHubPackError("artifact_path parent directories must not be symlinks")
    try:
        if existing:
            resolved = path.resolve(strict=True)
            if not resolved.is_file() or path.is_symlink():
                raise GitHubPackError("artifact_path must identify a regular non-symlink file")
        else:
            parent = path.parent.resolve(strict=True)
            resolved = parent / path.name
            if path.exists() or path.is_symlink():
                raise GitHubPackError("download artifact_path must not already exist")
    except OSError:
        raise GitHubPackError("artifact_path or its parent is unavailable") from None
    if resolved != root and root not in resolved.parents:
        raise GitHubPackError("artifact_path must stay within ATTUNE_ARTIFACTS_DIR")
    return resolved


def _check_current_etag(client: GitHubClient, path: str, expected: str) -> None:
    _, meta = client.request("GET", path)
    if meta.get("etag") != expected:
        raise GitHubPackError("resource ETag changed; read it again before mutating")


def _execute(client: GitHubClient, operation: str, params: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    owner, repository, repo_name = (None, None, None)
    if operation not in {"repository_list", "repository_create", "team_list", "team_get", "team_member_list", "team_member_add", "team_member_remove"}:
        owner, repository, repo_name = _repo(params)
    repo_path = f"/repos/{owner}/{repository}" if owner else ""

    if operation == "repository_get":
        return client.request("GET", repo_path, headers=_etag_headers(params))
    if operation == "repository_list":
        raw_owner = _string(params, "owner")
        owner_segment = _segment(raw_owner, "owner")
        owner_type = _enum(params, "owner_type", {"organization", "user"})
        query, cap = _query_with_pagination(params, ("type", "sort", "direction"))
        route = "orgs" if owner_type == "organization" else "users"
        return client.request("GET", f"/{route}/{owner_segment}/repos", query=query, paginate=True, max_results=cap)
    if operation == "repository_create":
        raw_owner = _string(params, "owner")
        owner_segment = _segment(raw_owner, "owner")
        owner_type = _enum(params, "owner_type", {"organization", "user"})
        if owner_type == "user":
            viewer, _ = client.request("GET", "/user")
            if not isinstance(viewer, dict) or viewer.get("login", "").lower() != raw_owner.lower():
                raise GitHubPackError("owner does not match the authenticated user")
            path = "/user/repos"
        else:
            path = f"/orgs/{owner_segment}/repos"
        body = _optional_body(params, ("name", "description", "homepage", "private", "visibility", "has_issues", "has_projects", "has_wiki", "is_template", "auto_init", "gitignore_template", "license_template", "allow_squash_merge", "allow_merge_commit", "allow_rebase_merge", "delete_branch_on_merge"))
        _string(params, "name")
        return client.request("POST", path, body=body)
    if operation == "repository_update":
        body = _optional_body(params, ("name", "description", "homepage", "private", "visibility", "has_issues", "has_projects", "has_wiki", "is_template", "default_branch", "allow_squash_merge", "allow_merge_commit", "allow_rebase_merge", "delete_branch_on_merge", "archived"))
        if not body:
            raise GitHubPackError("at least one repository update field is required")
        return client.request("PATCH", repo_path, body=body, headers=_etag_headers(params, "expected_etag"))
    if operation == "repository_delete":
        _confirm(params, f"DELETE_REPOSITORY:{repo_name}")
        return client.request("DELETE", repo_path)

    if operation in {"issue_get", "issue_list", "issue_create", "issue_update"}:
        if operation == "issue_get":
            number = _integer(params, "issue_number", None, 1, 2**31 - 1)
            return client.request("GET", f"{repo_path}/issues/{number}", headers=_etag_headers(params))
        if operation == "issue_list":
            query, cap = _query_with_pagination(params, ("milestone", "state", "assignee", "creator", "mentioned", "labels", "sort", "direction", "since"))
            return client.request("GET", f"{repo_path}/issues", query=query, paginate=True, max_results=cap)
        if operation == "issue_create":
            _string(params, "title")
            body = _optional_body(params, ("title", "body", "milestone", "labels", "assignees"))
            return client.request("POST", f"{repo_path}/issues", body=body)
        number = _integer(params, "issue_number", None, 1, 2**31 - 1)
        body = _optional_body(params, ("title", "body", "state", "state_reason", "milestone", "labels", "assignees"))
        if not body:
            raise GitHubPackError("at least one issue update field is required")
        return client.request("PATCH", f"{repo_path}/issues/{number}", body=body, headers=_etag_headers(params, "expected_etag"))

    if operation in {"comment_list", "comment_create", "comment_update", "comment_delete"}:
        if operation == "comment_list":
            number = _integer(params, "issue_number", None, 1, 2**31 - 1)
            query, cap = _query_with_pagination(params, ("since",))
            return client.request("GET", f"{repo_path}/issues/{number}/comments", query=query, paginate=True, max_results=cap)
        if operation == "comment_create":
            number = _integer(params, "issue_number", None, 1, 2**31 - 1)
            body = _string(params, "body")
            return client.request("POST", f"{repo_path}/issues/{number}/comments", body={"body": body})
        comment_id = _integer(params, "comment_id", None, 1, 2**63 - 1)
        path = f"{repo_path}/issues/comments/{comment_id}"
        if operation == "comment_update":
            return client.request("PATCH", path, body={"body": _string(params, "body")}, headers=_etag_headers(params, "expected_etag"))
        _confirm(params, f"DELETE_COMMENT:{repo_name}:{comment_id}")
        return client.request("DELETE", path)

    if operation in {"label_list", "label_create", "label_delete", "issue_labels_set"}:
        if operation == "label_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", f"{repo_path}/labels", query=query, paginate=True, max_results=cap)
        if operation == "label_create":
            name, color = _string(params, "name"), _string(params, "color")
            if not _HEX_COLOR.fullmatch(color):
                raise GitHubPackError("color must be exactly six hexadecimal characters without '#'")
            body = {"name": name, "color": color}
            if "description" in params:
                body["description"] = params["description"]
            return client.request("POST", f"{repo_path}/labels", body=body)
        if operation == "issue_labels_set":
            number = _integer(params, "issue_number", None, 1, 2**31 - 1)
            labels = _list(params, "labels")
            _confirm(params, f"SET_ISSUE_LABELS:{repo_name}:{number}:{','.join(sorted(labels))}")
            return client.request("PUT", f"{repo_path}/issues/{number}/labels", body={"labels": labels})
        name = _string(params, "name")
        _confirm(params, f"DELETE_LABEL:{repo_name}:{name}")
        return client.request("DELETE", f"{repo_path}/labels/{_segment(name, 'name')}")

    if operation in {"pull_get", "pull_list", "pull_create", "pull_update", "pull_review_list", "pull_review_create", "pull_merge"}:
        if operation == "pull_list":
            query, cap = _query_with_pagination(params, ("state", "head", "base", "sort", "direction"))
            return client.request("GET", f"{repo_path}/pulls", query=query, paginate=True, max_results=cap)
        if operation == "pull_create":
            _string(params, "title")
            _string(params, "head")
            _string(params, "base")
            return client.request("POST", f"{repo_path}/pulls", body=_optional_body(params, ("title", "head", "base", "body", "draft", "maintainer_can_modify")))
        number = _integer(params, "pull_number", None, 1, 2**31 - 1)
        path = f"{repo_path}/pulls/{number}"
        if operation == "pull_get":
            return client.request("GET", path, headers=_etag_headers(params))
        if operation == "pull_update":
            body = _optional_body(params, ("title", "body", "state", "base", "maintainer_can_modify"))
            if not body:
                raise GitHubPackError("at least one pull request update field is required")
            return client.request("PATCH", path, body=body, headers=_etag_headers(params, "expected_etag"))
        if operation == "pull_review_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", path + "/reviews", query=query, paginate=True, max_results=cap)
        expected_sha = _string(params, "expected_head_sha")
        current, _ = client.request("GET", path)
        current_sha = current.get("head", {}).get("sha") if isinstance(current, dict) else None
        if current_sha != expected_sha:
            raise GitHubPackError("pull request head changed; review the new head before mutating")
        if operation == "pull_review_create":
            event = _enum(params, "event", {"APPROVE", "COMMENT", "REQUEST_CHANGES"})
            body = {"event": event, "commit_id": expected_sha}
            if "body" in params:
                body["body"] = params["body"]
            return client.request("POST", path + "/reviews", body=body)
        method = _enum(params, "merge_method", {"merge", "rebase", "squash"}, "merge")
        _confirm(params, f"MERGE:{repo_name}:{number}:{expected_sha}:{method}")
        body = {"sha": expected_sha, "merge_method": method}
        for key in ("commit_title", "commit_message"):
            if key in params:
                body[key] = params[key]
        return client.request("PUT", path + "/merge", body=body)

    if operation in {"branch_list", "branch_create", "branch_delete", "protection_get", "protection_update", "protection_delete"}:
        if operation == "branch_list":
            query, cap = _query_with_pagination(params, ("protected",))
            return client.request("GET", f"{repo_path}/branches", query=query, paginate=True, max_results=cap)
        branch = _string(params, "branch")
        encoded = quote(branch, safe="")
        if operation == "branch_create":
            source = _string(params, "source_branch")
            source_data, _ = client.request("GET", f"{repo_path}/git/ref/heads/{quote(source, safe='')}")
            sha = source_data.get("object", {}).get("sha") if isinstance(source_data, dict) else None
            if not isinstance(sha, str):
                raise GitHubPackError("source branch response did not contain a commit SHA")
            return client.request("POST", f"{repo_path}/git/refs", body={"ref": f"refs/heads/{branch}", "sha": sha})
        if operation == "branch_delete":
            _confirm(params, f"DELETE_BRANCH:{repo_name}:{branch}")
            return client.request("DELETE", f"{repo_path}/git/refs/heads/{encoded}")
        path = f"{repo_path}/branches/{encoded}/protection"
        if operation == "protection_get":
            return client.request("GET", path, headers=_etag_headers(params))
        expected_etag = _string(params, "expected_etag")
        _check_current_etag(client, path, expected_etag)
        if operation == "protection_delete":
            _confirm(params, f"DELETE_PROTECTION:{repo_name}:{branch}:{expected_etag}")
            return client.request("DELETE", path, headers={"If-Match": expected_etag})
        protection = _object(params, "protection")
        required = {"required_status_checks", "enforce_admins", "required_pull_request_reviews", "restrictions"}
        if not required.issubset(protection):
            raise GitHubPackError("protection must include all replacement fields: enforce_admins, required_pull_request_reviews, required_status_checks, restrictions")
        _confirm(params, f"UPDATE_PROTECTION:{repo_name}:{branch}:{expected_etag}")
        return client.request("PUT", path, body=protection, headers={"If-Match": expected_etag})

    if operation in {"content_get", "content_put", "content_delete"}:
        path_value = _string(params, "path")
        path = f"{repo_path}/contents/{_content_path(path_value)}"
        if operation == "content_get":
            query = {"ref": params["ref"]} if params.get("ref") else None
            return client.request("GET", path, query=query, headers=_etag_headers(params))
        message = _string(params, "message")
        branch = _string(params, "branch", optional=True)
        body: dict[str, Any] = {"message": message}
        if branch:
            body["branch"] = branch
        if operation == "content_delete":
            sha = _string(params, "sha")
            body["sha"] = sha
            _confirm(params, f"DELETE_CONTENT:{repo_name}:{path_value}:{sha}")
            return client.request("DELETE", path, body=body)
        content = _string(params, "content")
        encoding = _enum(params, "content_encoding", {"base64", "utf-8"}, "utf-8")
        if encoding == "utf-8":
            encoded_content = base64.b64encode(content.encode()).decode()
        else:
            try:
                base64.b64decode(content, validate=True)
            except (binascii.Error, ValueError):
                raise GitHubPackError("content is not valid base64") from None
            encoded_content = content
        body["content"] = encoded_content
        if params.get("sha"):
            body["sha"] = _string(params, "sha")
        if bool(params.get("committer_name")) != bool(params.get("committer_email")):
            raise GitHubPackError("committer_name and committer_email must be supplied together")
        if params.get("committer_name"):
            body["committer"] = {"name": _string(params, "committer_name"), "email": _string(params, "committer_email")}
        return client.request("PUT", path, body=body)

    if operation in {"commit_list", "commit_get", "commit_status_list", "commit_status_create"}:
        if operation == "commit_list":
            query, cap = _query_with_pagination(params, ("sha", "path", "author", "committer", "since", "until"))
            return client.request("GET", f"{repo_path}/commits", query=query, paginate=True, max_results=cap)
        ref = _string(params, "ref")
        encoded = quote(ref, safe="")
        if operation == "commit_get":
            return client.request("GET", f"{repo_path}/commits/{encoded}", headers=_etag_headers(params))
        if operation == "commit_status_list":
            return client.request("GET", f"{repo_path}/commits/{encoded}/status", headers=_etag_headers(params))
        state = _enum(params, "state", {"error", "expected", "failure", "pending", "success"})
        body = _optional_body(params, ("target_url", "description", "context"))
        body["state"] = state
        return client.request("POST", f"{repo_path}/statuses/{encoded}", body=body)

    if operation in {"release_list", "release_get", "release_create", "release_update", "release_delete"}:
        if operation == "release_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", f"{repo_path}/releases", query=query, paginate=True, max_results=cap)
        if operation == "release_create":
            _string(params, "tag_name")
            body = _optional_body(params, ("tag_name", "target_commitish", "name", "body", "draft", "prerelease", "generate_release_notes", "make_latest"))
            body.setdefault("draft", True)
            return client.request("POST", f"{repo_path}/releases", body=body)
        release_id = _integer(params, "release_id", None, 1, 2**63 - 1)
        path = f"{repo_path}/releases/{release_id}"
        if operation == "release_get":
            return client.request("GET", path, headers=_etag_headers(params))
        if operation == "release_update":
            body = _optional_body(params, ("tag_name", "target_commitish", "name", "body", "draft", "prerelease", "generate_release_notes", "make_latest"))
            if not body:
                raise GitHubPackError("at least one release update field is required")
            _confirm(params, f"UPDATE_RELEASE:{repo_name}:{release_id}")
            return client.request("PATCH", path, body=body, headers=_etag_headers(params, "expected_etag"))
        _confirm(params, f"DELETE_RELEASE:{repo_name}:{release_id}")
        return client.request("DELETE", path)

    if operation in {"release_asset_list", "release_asset_upload", "release_asset_download", "release_asset_delete"}:
        if operation == "release_asset_list":
            release_id = _integer(params, "release_id", None, 1, 2**63 - 1)
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", f"{repo_path}/releases/{release_id}/assets", query=query, paginate=True, max_results=cap)
        asset_id = _integer(params, "asset_id", None, 1, 2**63 - 1) if operation != "release_asset_upload" else None
        if operation == "release_asset_upload":
            release_id = _integer(params, "release_id", None, 1, 2**63 - 1)
            name = _string(params, "name")
            _segment(name, "name")
            content_type = _string(params, "content_type")
            source = _artifact_path(params, existing=True)
            return client.upload_asset(owner, repository, int(release_id), name, content_type, source)
        if operation == "release_asset_download":
            destination = _artifact_path(params, existing=False)
            limit = _integer(params, "max_download_bytes", 512 * 1024 * 1024, 1, MAX_DOWNLOAD_BYTES)
            return client.download(f"{repo_path}/releases/assets/{asset_id}", destination, int(limit))
        _confirm(params, f"DELETE_RELEASE_ASSET:{repo_name}:{asset_id}")
        return client.request("DELETE", f"{repo_path}/releases/assets/{asset_id}")

    if operation in {"deployment_list", "deployment_create", "deployment_status_list", "deployment_status_create"}:
        if operation == "deployment_list":
            query, cap = _query_with_pagination(params, ("sha", "ref", "task", "environment"))
            return client.request("GET", f"{repo_path}/deployments", query=query, paginate=True, max_results=cap)
        if operation == "deployment_create":
            ref = _string(params, "ref")
            environment = _string(params, "environment")
            required_contexts = _list(params, "required_contexts")
            auto_merge = _boolean(params, "auto_merge", False)
            _confirm(params, f"CREATE_DEPLOYMENT:{repo_name}:{ref}:{environment}")
            body = _optional_body(params, ("ref", "task", "description", "transient_environment", "production_environment"))
            body.update({"environment": environment, "auto_merge": auto_merge, "required_contexts": required_contexts})
            return client.request("POST", f"{repo_path}/deployments", body=body)
        deployment_id = _integer(params, "deployment_id", None, 1, 2**63 - 1)
        path = f"{repo_path}/deployments/{deployment_id}/statuses"
        if operation == "deployment_status_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", path, query=query, paginate=True, max_results=cap)
        state = _enum(params, "state", {"error", "failure", "inactive", "in_progress", "pending", "queued", "success"})
        environment = _string(params, "environment", optional=True) or ""
        _confirm(params, f"CREATE_DEPLOYMENT_STATUS:{repo_name}:{deployment_id}:{state}:{environment}")
        body = _optional_body(params, ("state", "target_url", "log_url", "description", "environment", "environment_url", "auto_inactive"))
        return client.request("POST", path, body=body)

    if operation in {"workflow_list", "workflow_get", "workflow_dispatch", "workflow_run_list", "workflow_run_get", "workflow_run_control"}:
        if operation == "workflow_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", f"{repo_path}/actions/workflows", query=query, paginate=True, collection_key="workflows", max_results=cap)
        if operation == "workflow_run_list":
            query, cap = _query_with_pagination(params, ("actor", "branch", "event", "status", "created", "exclude_pull_requests", "check_suite_id", "head_sha"))
            return client.request("GET", f"{repo_path}/actions/runs", query=query, paginate=True, collection_key="workflow_runs", max_results=cap)
        if operation in {"workflow_run_get", "workflow_run_control"}:
            run_id = _integer(params, "run_id", None, 1, 2**63 - 1)
            path = f"{repo_path}/actions/runs/{run_id}"
            if operation == "workflow_run_get":
                return client.request("GET", path, headers=_etag_headers(params))
            control = _enum(params, "control", {"cancel", "rerun", "rerun-failed-jobs"})
            _confirm(params, f"WORKFLOW_RUN:{control.upper()}:{repo_name}:{run_id}")
            return client.request("POST", path + f"/{control}")
        workflow_id = _string(params, "workflow_id")
        path = f"{repo_path}/actions/workflows/{quote(workflow_id, safe='')}"
        if operation == "workflow_get":
            return client.request("GET", path, headers=_etag_headers(params))
        ref = _string(params, "ref")
        inputs = params.get("inputs", {})
        if not isinstance(inputs, dict) or any(not isinstance(key, str) or not isinstance(value, (str, bool, int, float)) for key, value in inputs.items()):
            raise GitHubPackError("inputs must be an object of scalar workflow inputs")
        _confirm(params, f"DISPATCH_WORKFLOW:{repo_name}:{workflow_id}:{ref}")
        return client.request("POST", path + "/dispatches", body={"ref": ref, "inputs": inputs})

    if operation in {"artifact_list", "artifact_download", "artifact_delete"}:
        if operation == "artifact_list":
            query, cap = _query_with_pagination(params, ("name",))
            run_id = _integer(params, "run_id", None, 1, 2**63 - 1)
            path = f"{repo_path}/actions/runs/{run_id}/artifacts" if run_id else f"{repo_path}/actions/artifacts"
            return client.request("GET", path, query=query, paginate=True, collection_key="artifacts", max_results=cap)
        artifact_id = _integer(params, "artifact_id", None, 1, 2**63 - 1)
        if operation == "artifact_download":
            destination = _artifact_path(params, existing=False)
            limit = _integer(params, "max_download_bytes", 512 * 1024 * 1024, 1, MAX_DOWNLOAD_BYTES)
            return client.download(f"{repo_path}/actions/artifacts/{artifact_id}/zip", destination, int(limit))
        _confirm(params, f"DELETE_ARTIFACT:{repo_name}:{artifact_id}")
        return client.request("DELETE", f"{repo_path}/actions/artifacts/{artifact_id}")

    if operation in {"team_list", "team_get", "team_member_list", "team_member_add", "team_member_remove"}:
        organization_raw = _string(params, "organization")
        organization = _segment(organization_raw, "organization")
        if operation == "team_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", f"/orgs/{organization}/teams", query=query, paginate=True, max_results=cap)
        team_raw = _string(params, "team_slug")
        team = _segment(team_raw, "team_slug")
        path = f"/orgs/{organization}/teams/{team}"
        if operation == "team_get":
            return client.request("GET", path, headers=_etag_headers(params))
        if operation == "team_member_list":
            query, cap = _query_with_pagination(params, ("role",))
            return client.request("GET", path + "/members", query=query, paginate=True, max_results=cap)
        username_raw = _string(params, "username")
        username = _segment(username_raw, "username")
        membership = path + f"/memberships/{username}"
        if operation == "team_member_add":
            role = _enum(params, "role", {"maintainer", "member"}, "member")
            _confirm(params, f"ADD_TEAM_MEMBER:{organization_raw}:{team_raw}:{username_raw}:{role}")
            return client.request("PUT", membership, body={"role": role})
        _confirm(params, f"REMOVE_TEAM_MEMBER:{organization_raw}:{team_raw}:{username_raw}")
        return client.request("DELETE", membership)

    if operation in {"webhook_list", "webhook_create", "webhook_delete"}:
        if operation == "webhook_list":
            query, cap = _query_with_pagination(params, ())
            return client.request("GET", f"{repo_path}/hooks", query=query, paginate=True, max_results=cap)
        if operation == "webhook_delete":
            hook_id = _integer(params, "hook_id", None, 1, 2**63 - 1)
            _confirm(params, f"DELETE_WEBHOOK:{repo_name}:{hook_id}")
            return client.request("DELETE", f"{repo_path}/hooks/{hook_id}")
        webhook_url = _string(params, "webhook_url")
        parsed = urlsplit(webhook_url)
        try:
            port = parsed.port
        except ValueError:
            raise GitHubPackError("webhook_url has an invalid port") from None
        host = (parsed.hostname or "").lower()
        allowlist = client.credential.get("webhook_host_allowlist", [])
        if (
            parsed.scheme != "https"
            or not host
            or port not in {None, 443}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or host not in {item.lower() for item in allowlist if isinstance(item, str)}
        ):
            raise GitHubPackError("webhook_url must be an exact allowlisted HTTPS host without credentials, query or fragment")
        secret = client.credential.get("webhook_secret")
        if not isinstance(secret, str) or len(secret) < 16 or any(ord(char) < 32 for char in secret):
            raise GitHubPackError("credential webhook_secret must contain at least 16 characters")
        events = _list(params, "events")
        _confirm(params, f"CREATE_WEBHOOK:{repo_name}:{host}:{','.join(sorted(events))}")
        body = {"name": "web", "active": _boolean(params, "active", True), "events": events, "config": {"url": webhook_url, "content_type": "json", "insecure_ssl": "0", "secret": secret}}
        return client.request("POST", f"{repo_path}/hooks", body=body)

    raise GitHubPackError("unsupported GitHub action")


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    timeout = _integer(params, "timeout_seconds", 30, 1, 120)
    retries = _integer(params, "read_retries", 1, 0, 2)
    credential_key = params.get("credential_key", DEFAULT_CREDENTIAL_KEY)
    credential = _fetch_key(credential_key)
    with _tls_verify(credential) as verify:
        client = GitHubClient(credential, int(timeout or 30), int(retries or 0), verify)
        data, meta = _execute(client, operation, params)
    return {"operation": operation, "data": data, "meta": meta}
