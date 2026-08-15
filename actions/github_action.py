#!/usr/bin/env python3
"""Shared stdin/JSON entry point for all GitHub actions."""

from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.github_client import GitHubPackError, execute_action  # noqa: E402


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise GitHubPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        json.dump(execute_action(operation, params), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except json.JSONDecodeError:
        print("github action failed: invalid JSON action parameters", file=sys.stderr)
    except GitHubPackError as exc:
        print(f"github action failed: {exc}", file=sys.stderr)
    except Exception as exc:
        # Unknown client errors can include headers, URLs, or remote response data.
        print(f"github action failed: {type(exc).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
