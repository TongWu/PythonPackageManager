"""Utility functions to assess package community activity timelines.

This module inspects PyPI metadata and GitHub repository activity to derive
two timestamps per package:

1. The most recent release date for the package's *current major* version.
2. The most recent activity date for the package overall, defined as the
   latest timestamp among the newest release and community activity on
   GitHub (issues, pull requests, or commits).

The helper functions accept package/version pairs that can be sourced from
`requirements_full_list.txt` or a CSV file with two columns
`[Package Name, Version]`.
"""

from __future__ import annotations

import csv
import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse

import json
import hashlib
from time import sleep
from pathlib import Path
from random import random

import requests
from packaging.version import InvalidVersion, Version
from dotenv import load_dotenv

from utils.SGTUtils import SGTFormatter
from utils.ConfigUtils import parse_requirements
from utils.PyPiUtils import GetPyPiInfo

load_dotenv(dotenv_path=".env")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False

_SESSION = requests.Session()
_GITHUB_API = "https://api.github.com"
_GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
_GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "PythonPackageManager/CommunityActivityUtils",
}

# --- Simple persistent cache for ETags & JSON payloads (file-based) ---
_CACHE_PATH = Path(".gh_api_cache.json")
try:
    _ETAG_CACHE = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
except Exception:
    _ETAG_CACHE = {}  # {key: {"etag": "...", "last_modified": "...", "payload": {...}, "fetched_at": "..."}}

def _cache_key(url: str, params: Optional[dict]) -> str:
    """Stable key for (url, sorted params)."""
    h = hashlib.sha256()
    h.update(url.encode("utf-8"))
    if params:
        h.update(json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return h.hexdigest()

def _cache_get(key: str):
    return _ETAG_CACHE.get(key)

def _cache_put(key: str, etag: Optional[str], last_mod: Optional[str], payload: Optional[object]):
    _ETAG_CACHE[key] = {
        "etag": etag,
        "last_modified": last_mod,
        "payload": payload,
        "fetched_at": datetime.now(timezone.utc).isoformat()
    }
    try:
        _CACHE_PATH.write_text(json.dumps(_ETAG_CACHE), encoding="utf-8")
    except Exception:
        pass

if _GITHUB_TOKEN:
    _GITHUB_HEADERS["Authorization"] = f"Bearer {_GITHUB_TOKEN}"


def load_packages_from_requirements(path: str) -> list[Tuple[str, str]]:
    """Return package/version pairs parsed from a requirements file."""

    pkgs = parse_requirements(path)
    return list(pkgs.items())


def load_packages_from_csv(path: str, package_column: str = "Package Name", version_column: str = "Version") -> list[Tuple[str, str]]:
    """Return package/version pairs parsed from a CSV file."""

    pairs: list[Tuple[str, str]] = []
    with open(path, newline='', encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            pkg = (row.get(package_column) or "").strip()
            ver = (row.get(version_column) or "").strip()
            if pkg:
                pairs.append((pkg, ver or "unknown"))
    return pairs


def get_activity_dates(package: str, current_version: str, pypi_info: Optional[dict] = None) -> Tuple[str, str]:
    """Compute formatted activity timestamps for a package.

    Args:
        package: Package name.
        current_version: Version currently in use.
        pypi_info: Optional pre-fetched PyPI metadata.

    Returns:
        Tuple of formatted strings:
        (last_active_current_major, last_active_package)
    """

    if not pypi_info:
        pypi_info = GetPyPiInfo(package)

    if not pypi_info:
        return "Unknown", "Unknown"

    major_release_date = _get_latest_release_for_current_major(pypi_info, current_version)
    latest_release_date = _get_latest_release_overall(pypi_info)

    repo_url = _extract_github_repo(pypi_info)
    repo_activity = _get_repo_last_activity(repo_url) if repo_url else None

    package_activity = _max_datetime(latest_release_date, repo_activity)

    return _format_date(major_release_date), _format_date(package_activity)


def build_activity_map(packages: Iterable[Tuple[str, str]]) -> dict[str, dict[str, str]]:
    """Return activity metadata for multiple packages.

    The result is a dictionary keyed by package name (lowercase) containing
    formatted timestamps and resolved source URLs. This helper is primarily
    intended for standalone use of the utility module.
    """

    results: dict[str, dict[str, str]] = {}
    for package, version in packages:
        info = GetPyPiInfo(package)
        major_date, package_date = get_activity_dates(package, version, info)
        results[package.lower()] = {
            "package": package,
            "current_version": version,
            "last_active_current_major": major_date,
            "last_active_package": package_date,
            "github_repo": _normalize_github_url(_extract_github_repo(info)) or "",
            "pypi_url": f"https://pypi.org/project/{package}/",
        }
    return results


def _get_latest_release_for_current_major(pypi_info: dict, current_version: str) -> Optional[datetime]:
    try:
        parsed_current = Version(current_version)
    except InvalidVersion:
        logger.debug("Invalid version string for %s: %s", pypi_info.get('info', {}).get('name', 'unknown'), current_version)
        return None

    releases = pypi_info.get('releases', {}) or {}
    timestamps: list[datetime] = []
    for version_str, files in releases.items():
        try:
            parsed_version = Version(version_str)
        except InvalidVersion:
            continue
        if parsed_version.major != parsed_current.major:
            continue
        release_time = _extract_latest_upload_time(files)
        if release_time:
            timestamps.append(release_time)

    if timestamps:
        return max(timestamps)

    # Fall back to the current version's release time if available via `urls`.
    release_time = _get_release_time_for_version(pypi_info, current_version)
    return release_time


def _get_latest_release_overall(pypi_info: dict) -> Optional[datetime]:
    releases = pypi_info.get('releases', {}) or {}
    latest_version: Optional[Version] = None
    latest_timestamp: Optional[datetime] = None

    for version_str, files in releases.items():
        try:
            parsed_version = Version(version_str)
        except InvalidVersion:
            continue

        release_time = _extract_latest_upload_time(files)
        if not release_time:
            continue

        if latest_version is None or parsed_version > latest_version:
            latest_version = parsed_version
            latest_timestamp = release_time
        elif parsed_version == latest_version and latest_timestamp and release_time > latest_timestamp:
            latest_timestamp = release_time

    if latest_timestamp:
        return latest_timestamp

    # Fallback to the URLs section which usually contains the latest release files.
    urls = pypi_info.get('urls', []) or []
    url_times = [_parse_iso_datetime(url.get('upload_time_iso_8601') or url.get('upload_time')) for url in urls]
    url_times = [t for t in url_times if t]
    if url_times:
        return max(url_times)

    return None


def _get_release_time_for_version(pypi_info: dict, version_str: str) -> Optional[datetime]:
    releases = pypi_info.get('releases', {}) or {}
    release_files = releases.get(version_str)
    if release_files:
        return _extract_latest_upload_time(release_files)

    urls = pypi_info.get('urls', []) or []
    matching_times = [
        _parse_iso_datetime(entry.get('upload_time_iso_8601') or entry.get('upload_time'))
        for entry in urls
        if entry.get('filename', '').startswith(f"{pypi_info.get('info', {}).get('name', '')}-{version_str}")
    ]
    matching_times = [t for t in matching_times if t]
    if matching_times:
        return max(matching_times)

    return None


def _extract_latest_upload_time(files: Iterable[dict]) -> Optional[datetime]:
    timestamps = [
        _parse_iso_datetime(entry.get('upload_time_iso_8601') or entry.get('upload_time'))
        for entry in files
    ]
    timestamps = [t for t in timestamps if t]
    return max(timestamps) if timestamps else None


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        sanitized = value.strip()
        if sanitized.endswith('Z'):
            sanitized = sanitized[:-1] + '+00:00'
        dt = datetime.fromisoformat(sanitized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        logger.debug("Failed to parse datetime: %s", value)
        return None


def _format_date(value: Optional[datetime]) -> str:
    if not value:
        return "Unknown"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _max_datetime(*values: Optional[datetime]) -> Optional[datetime]:
    present = [v for v in values if v is not None]
    if not present:
        return None
    return max(present)


def _extract_github_repo(pypi_info: dict) -> Optional[str]:
    info = pypi_info.get('info', {}) or {}
    candidates = []

    project_urls = info.get('project_urls') or {}
    for url in project_urls.values():
        if isinstance(url, str) and 'github.com' in url.lower():
            candidates.append(url)

    home_page = info.get('home_page')
    if isinstance(home_page, str) and 'github.com' in home_page.lower():
        candidates.append(home_page)

    bugtrack_url = info.get('bugtrack_url')
    if isinstance(bugtrack_url, str) and 'github.com' in bugtrack_url.lower():
        candidates.append(bugtrack_url)

    for url in candidates:
        normalized = _normalize_github_url(url)
        if normalized:
            return normalized
    return None


def _normalize_github_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None

    cleaned = url.strip()
    if cleaned.startswith('git+'):  # e.g., git+https://github.com/...
        cleaned = cleaned[4:]
    if cleaned.startswith('git://'):
        cleaned = 'https://' + cleaned[6:]

    if not cleaned.startswith('http://') and not cleaned.startswith('https://'):
        cleaned = 'https://' + cleaned.lstrip('/:')

    parsed = urlparse(cleaned)
    hostname = (parsed.netloc or '').lower()
    if hostname not in {'github.com', 'www.github.com'}:
        return None

    path = parsed.path.strip('/')
    if not path:
        return None

    parts = path.split('/')
    if len(parts) < 2:
        return None

    owner, repo = parts[0], parts[1]
    repo = repo.replace('.git', '')
    return f"https://github.com/{owner}/{repo}"


def _repo_full_name(repo_url: str) -> Optional[str]:
    parsed = urlparse(repo_url)
    path = parsed.path.strip('/')
    if not path:
        return None
    parts = path.split('/')
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    return f"{owner}/{repo}"


@lru_cache(maxsize=512)
def _get_repo_last_activity(repo_url: Optional[str]) -> Optional[datetime]:
    if not repo_url:
        return None

    full_name = _repo_full_name(repo_url)
    if not full_name:
        return None

    # 1) Try GraphQL single-shot query first (fewer requests)
    gql_ts = _github_graphql_repo_activity(full_name)
    if gql_ts:
        return gql_ts

    # 2) Fallback to REST: /repos/{full_name} + last updated issue
    metadata = _github_get(f"/repos/{full_name}")
    if not metadata:
        return None

    timestamps = []
    for key in ('pushed_at', 'updated_at'):
        timestamps.append(_parse_iso_datetime(metadata.get(key)))

    issues_timestamp = _get_latest_issue_update(full_name)
    if issues_timestamp:
        timestamps.append(issues_timestamp)

    return _max_datetime(*timestamps)
   

def _get_latest_issue_update(full_name: str) -> Optional[datetime]:
    response = _github_get(
        f"/repos/{full_name}/issues",
        params={'state': 'all', 'sort': 'updated', 'direction': 'desc', 'per_page': 1}
    )

    if isinstance(response, list) and response:
        return _parse_iso_datetime(response[0].get('updated_at'))

    return None

def _github_graphql_repo_activity(full_name: str) -> Optional[datetime]:
    """
    Query GitHub GraphQL v4 for repository activity in a single request.
    Fields: repository.pushedAt, repository.updatedAt, last issue updatedAt.
    Falls back to None on errors; caller may try REST path.
    """
    if not _GITHUB_TOKEN:
        return None  # GraphQL requires auth

    # Prepare GraphQL endpoint and headers
    gql_url = f"{_GITHUB_API.replace('api.', '')}/graphql"
    headers = {
        "Authorization": f"Bearer {_GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": _GITHUB_HEADERS.get("User-Agent", "Python"),
    }

    try:
        owner, repo = full_name.split("/", 1)
    except ValueError:
        return None

    # GraphQL query: one hop for activity
    query = """
    query($owner: String!, $name: String!) {
      rateLimit {
        limit
        remaining
        resetAt
        cost
      }
      repository(owner: $owner, name: $name) {
        pushedAt
        updatedAt
        issues(first: 1, orderBy: {field: UPDATED_AT, direction: DESC}, states: [OPEN, CLOSED]) {
          nodes { updatedAt }
        }
      }
    }
    """
    variables = {"owner": owner, "name": repo}

    # Backoff loop for secondary rate limit on GraphQL
    max_retries = 5
    backoff = 2.0

    for attempt in range(max_retries):
        try:
            resp = _SESSION.post(gql_url, headers=headers, json={"query": query, "variables": variables}, timeout=12)
        except requests.RequestException as exc:
            logger.warning("GitHub GraphQL request failed: %s", exc)
            sleep(backoff * (1 + random()))
            backoff = min(backoff * 2, 600)
            continue

        # GraphQL uses 200 even for errors; inspect body
        if resp.status_code in (403, 429):
            ra = resp.headers.get("Retry-After")
            wait_sec = int(ra) if ra and ra.isdigit() else max(60, int(backoff))
            logger.warning("GraphQL secondary rate limit. Sleeping %ss", wait_sec)
            sleep(wait_sec)
            backoff = min(backoff * 2, 600)
            continue

        try:
            body = resp.json()
        except ValueError:
            logger.debug("Failed to parse GraphQL JSON")
            return None

        if "errors" in body and body["errors"]:
            # For example: abuse detection mechanism, rate limits, not found, etc.
            # Respect potential rate limit hints
            logger.debug("GraphQL errors: %s", body["errors"])
            sleep(backoff * (1 + random()))
            backoff = min(backoff * 2, 600)
            continue

        repo_node = body.get("data", {}).get("repository")
        if not repo_node:
            return None

        ts = []
        ts.append(_parse_iso_datetime(repo_node.get("pushedAt")))
        ts.append(_parse_iso_datetime(repo_node.get("updatedAt")))
        issues = repo_node.get("issues", {}).get("nodes") or []
        if issues:
            ts.append(_parse_iso_datetime(issues[0].get("updatedAt")))
        return _max_datetime(*ts)

    return None

def _github_get(path: str, params: Optional[dict] = None) -> Optional[object]:
    """GET GitHub REST v3 with ETag/Last-Modified caching and polite backoff."""
    url = f"{_GITHUB_API}{path}"
    key = _cache_key(url, params)

    # Build headers and attach conditional validators from cache
    headers = dict(_GITHUB_HEADERS)
    cached = _cache_get(key)
    if cached:
        if cached.get("etag"):
            headers["If-None-Match"] = cached["etag"]
        elif cached.get("last_modified"):
            headers["If-Modified-Since"] = cached["last_modified"]

    max_retries = 5
    backoff = 2.0  # seconds

    for attempt in range(max_retries):
        try:
            resp = _SESSION.get(url, headers=headers, params=params, timeout=10)
        except requests.RequestException as exc:
            logger.warning("GitHub request to %s failed: %s", url, exc)
            sleep(backoff * (1 + random()))
            backoff = min(backoff * 2, 600)
            continue

        status = resp.status_code

        # Handle primary & secondary rate limits
        if status in (403, 429):
            # Primary limit exhausted: wait until reset
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                reset = resp.headers.get("X-RateLimit-Reset")
                try:
                    reset_ts = int(reset)
                    wait_sec = max(0, reset_ts - int(datetime.now(timezone.utc).timestamp())) + 1
                except Exception:
                    wait_sec = 60
                logger.warning("Primary rate limit hit. Waiting %ss until reset.", wait_sec)
                sleep(wait_sec)
                continue

            # Secondary limit: honor Retry-After if present
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    wait_sec = int(ra)
                except ValueError:
                    wait_sec = 60
                logger.warning("Secondary rate limit. Retry-After=%ss", wait_sec)
                sleep(wait_sec)
                continue

            # Fallback: exponential backoff with jitter
            wait_sec = max(60, int(backoff))
            logger.warning("Secondary rate limit (no headers). Sleeping %ss", wait_sec)
            sleep(wait_sec)
            backoff = min(backoff * 2, 600)
            continue

        if status == 304 and cached:
            # 304 does not count against primary rate limit; return cached payload
            new_etag = resp.headers.get("ETag") or cached.get("etag")
            new_lm = resp.headers.get("Last-Modified") or cached.get("last_modified")
            _cache_put(key, new_etag, new_lm, cached.get("payload"))
            return cached.get("payload")

        if status >= 400:
            logger.debug("GitHub request to %s returned status %s", url, status)
            return None

        if resp.headers.get('Content-Type', '').startswith('application/json'):
            try:
                data = resp.json()
            except ValueError:
                logger.debug("Failed to decode GitHub JSON response from %s", url)
                return None
            _cache_put(key, resp.headers.get("ETag"), resp.headers.get("Last-Modified"), data)
            return data

        return None  # Non-JSON unexpected

    logger.warning("GitHub request to %s exhausted retries due to rate limiting.", url)
    return None



