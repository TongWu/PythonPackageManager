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

    metadata = _github_get(f"/repos/{full_name}")
    if not metadata:
        return None

    timestamps = []
    for key in ('pushed_at', 'updated_at'):
        timestamps.append(_parse_iso_datetime(metadata.get(key)))

    issues_timestamp = _get_latest_issue_update(full_name)
    if issues_timestamp:
        timestamps.append(issues_timestamp)

    activity_timestamp = _max_datetime(*timestamps)
    return activity_timestamp


def _get_latest_issue_update(full_name: str) -> Optional[datetime]:
    response = _github_get(
        f"/repos/{full_name}/issues",
        params={'state': 'all', 'sort': 'updated', 'direction': 'desc', 'per_page': 1}
    )

    if isinstance(response, list) and response:
        return _parse_iso_datetime(response[0].get('updated_at'))

    return None


def _github_get(path: str, params: Optional[dict] = None) -> Optional[object]:
    url = f"{_GITHUB_API}{path}"
    try:
        resp = _SESSION.get(url, headers=_GITHUB_HEADERS, params=params, timeout=10)
    except requests.RequestException as exc:
        logger.warning("GitHub request to %s failed: %s", url, exc)
        return None

    if resp.status_code == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
        reset = resp.headers.get('X-RateLimit-Reset')
        logger.warning("GitHub rate limit exceeded. Reset epoch: %s", reset)
        return None

    if resp.status_code >= 400:
        logger.debug("GitHub request to %s returned status %s", url, resp.status_code)
        return None

    if resp.headers.get('Content-Type', '').startswith('application/json'):
        try:
            return resp.json()
        except ValueError:
            logger.debug("Failed to decode GitHub JSON response from %s", url)
            return None

    return None


