#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate a CSV report describing outdated Python packages.

The script inspects the packages listed in ``requirements_full_list.txt`` (or a
user-supplied requirements file), compares their versions with what is
available on PyPI, and outputs a CSV report summarising upgrade options.  When
a newer major release exists, the script prefers suggesting a vulnerability
checked upgrade for the *second latest* major version (``T-1``).  If the
package already uses the latest major release (``T``) or no ``T-1`` upgrade is
available, a safe upgrade within the latest major is suggested instead.

The report also captures community activity dates using
``utils.CommunityActivityUtils``.  The resulting CSV is written to the current
working directory (or a specified output directory) with a filename of the
form ``OutdatedPackageAnalysis_YYYYMMDD.csv``.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from packaging.version import InvalidVersion, Version

from utils.CommunityActivityUtils import get_activity_dates
from utils.ConfigUtils import parse_requirements
from utils.PyPiUtils import GetPyPiInfo
from utils.SGTUtils import SGTFormatter
from utils.VersionSuggester import find_latest_safe_version_for_major

# ---------------------------------------------------------------------------
# Logging configuration

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(
    SGTFormatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
)
logger.addHandler(handler)
logger.propagate = False


# ---------------------------------------------------------------------------
# Constants

DEFAULT_REQUIREMENTS = Path("src/requirements_full_list.txt")
OUTPUT_TEMPLATE = "OutdatedPackageAnalysis_{:%Y%m%d}.csv"
CSV_COLUMNS = [
    "Package Name",
    "Current Version",
    "Is Major/Second Major Version",
    "Upgrade Available?",
    "Upgrade Instruction",
    "Last Active Date for current major version",
    "Last active date for package",
]


# ---------------------------------------------------------------------------
# Helper utilities

def _parse_versions(releases: dict[str, list]) -> list[tuple[Version, str]]:
    """Return parsed versions for the release mapping from PyPI."""

    parsed: list[tuple[Version, str]] = []
    for ver_str, files in (releases or {}).items():
        try:
            parsed_version = Version(ver_str)
        except InvalidVersion:
            continue

        if not files:
            # Some projects keep legacy releases without downloadable files on
            # PyPI.  Skip these entries as they are not installable.
            continue

        parsed.append((parsed_version, ver_str))

    parsed.sort(key=lambda item: item[0])
    return parsed


def _has_newer_in_major(
    parsed_versions: Iterable[tuple[Version, str]],
    target_major: int,
    current: Optional[Version],
) -> bool:
    """Return ``True`` if a higher version exists within ``target_major``."""

    for candidate, _ in parsed_versions:
        if candidate.major != target_major:
            continue
        if current and candidate.major == current.major and candidate <= current:
            continue
        return True
    return False


def _select_target_major(
    parsed_versions: list[tuple[Version, str]],
    current: Optional[Version],
) -> tuple[Optional[int], str, Optional[int]]:
    """Determine which major version should be used for upgrade suggestion."""

    if not parsed_versions:
        return None, "N/A", None

    majors = sorted({candidate.major for candidate, _ in parsed_versions})
    latest_major = majors[-1]
    second_latest_major = majors[-2] if len(majors) >= 2 else None

    if current is None:
        # Without a valid current version we cannot identify the precise major
        # relationship.  Default to the second latest major if available.
        if second_latest_major is not None:
            return second_latest_major, "Second Latest Major (T-1)", latest_major
        return latest_major, "Latest Major (T)", latest_major

    current_major = current.major

    if current_major == latest_major:
        if _has_newer_in_major(parsed_versions, latest_major, current):
            return latest_major, "Latest Major (T)", latest_major
        return None, "Latest Major (T)", latest_major

    if (
        second_latest_major is not None
        and second_latest_major >= current_major
        and _has_newer_in_major(parsed_versions, second_latest_major, current)
    ):
        label = (
            "Second Latest Major (T-1)"
            if second_latest_major > current_major
            else "Current Major (T)"
        )
        return second_latest_major, label, latest_major

    if _has_newer_in_major(parsed_versions, latest_major, current):
        return latest_major, "Latest Major (T)", latest_major

    return None, "N/A", latest_major


def _safe_version_for_major(
    package: str,
    current_version: str,
    all_versions: list[str],
    target_major: Optional[int],
    primary_label: str,
    fallback_major: Optional[int] = None,
    fallback_label: Optional[str] = None,
) -> tuple[Optional[str], str]:
    """Return vulnerability-free version suggestion and associated label."""

    safe_version: Optional[str] = None

    if target_major is not None:
        try:
            safe_version = asyncio.run(
                find_latest_safe_version_for_major(
                    package, current_version, all_versions, target_major
                )
            )
        except Exception as exc:  # pragma: no cover - network failure safety
            logger.warning(
                "Unable to determine safe version for %s (major %s): %s",
                package,
                target_major,
                exc,
            )
            safe_version = None

    if safe_version is not None:
        return safe_version, primary_label or "N/A"

    if fallback_major is not None and fallback_major != target_major:
        try:
            safe_version = asyncio.run(
                find_latest_safe_version_for_major(
                    package, current_version, all_versions, fallback_major
                )
            )
        except Exception as exc:  # pragma: no cover - network failure safety
            logger.warning(
                "Unable to determine fallback safe version for %s (major %s): %s",
                package,
                fallback_major,
                exc,
            )
            safe_version = None

        if safe_version is not None:
            return safe_version, fallback_label or primary_label or "N/A"

    return None, primary_label or "N/A"


def _analyse_package(package: str, current_version: str) -> dict[str, str]:
    """Collect metadata for a single package."""

    logger.info("Processing %s==%s", package, current_version)
    row = {
        "Package Name": package,
        "Current Version": current_version,
        "Is Major/Second Major Version": "N/A",
        "Upgrade Available?": "Unknown",
        "Upgrade Instruction": "Package metadata unavailable",
        "Last Active Date for current major version": "Unknown",
        "Last active date for package": "Unknown",
    }

    info = GetPyPiInfo(package)
    if info:
        major_activity, package_activity = get_activity_dates(
            package, current_version, info
        )
        row["Last Active Date for current major version"] = major_activity
        row["Last active date for package"] = package_activity
    else:
        return row

    parsed_versions = _parse_versions(info.get("releases", {}) or {})
    if not parsed_versions:
        row["Upgrade Instruction"] = "No valid releases found on PyPI"
        row["Upgrade Available?"] = "No"
        return row

    all_versions = [ver_str for _, ver_str in parsed_versions]

    try:
        current_parsed = Version(current_version)
    except InvalidVersion:
        current_parsed = None

    if current_parsed is not None:
        has_newer = any(candidate > current_parsed for candidate, _ in parsed_versions)
        row["Upgrade Available?"] = "Yes" if has_newer else "No"
    else:
        row["Upgrade Available?"] = "Unknown"

    if row["Upgrade Available?"] != "Yes":
        row["Upgrade Instruction"] = (
            "Up-to-date" if row["Upgrade Available?"] == "No" else "Unable to determine"
        )
        return row

    target_major, major_label, latest_major = _select_target_major(
        parsed_versions, current_parsed
    )
    fallback_major: Optional[int] = None
    fallback_label: Optional[str] = None

    if (
        latest_major is not None
        and target_major is not None
        and latest_major != target_major
    ):
        fallback_major = latest_major
        fallback_label = "Latest Major (T)"

    safe_version, label_from_safe = _safe_version_for_major(
        package,
        current_version,
        all_versions,
        target_major,
        major_label,
        fallback_major,
        fallback_label,
    )

    if safe_version:
        major_label = label_from_safe or major_label
        row["Upgrade Instruction"] = f"Upgrade to {safe_version} ({major_label})"
    else:
        row["Upgrade Instruction"] = "No vulnerability-free upgrade identified"

    row["Is Major/Second Major Version"] = major_label or "N/A"

    return row


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a CSV report of outdated packages based on PyPI metadata."
    )
    parser.add_argument(
        "--requirements",
        default=str(DEFAULT_REQUIREMENTS),
        help=(
            "Path to the requirements file listing packages and pinned versions. "
            "Defaults to src/requirements_full_list.txt"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory where the CSV report should be written (default: current directory).",
    )
    return parser


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()

    requirements_path = Path(args.requirements)
    if not requirements_path.exists():
        logger.error("Requirements file not found: %s", requirements_path)
        return 1

    packages = parse_requirements(str(requirements_path))
    if not packages:
        logger.warning("No packages found in %s", requirements_path)
        return 0

    output_directory = Path(args.output_dir).expanduser()
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / OUTPUT_TEMPLATE.format(datetime.now())

    rows = [_analyse_package(pkg, version) for pkg, version in packages.items()]

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    logger.info("Report written to %s", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
