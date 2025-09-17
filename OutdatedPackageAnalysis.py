#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate a CSV report highlighting outdated Python packages.

The script inspects the packages listed in ``requirements_full_list.txt`` and
identifies entries that have newer releases available on PyPI.  For each
outdated package it determines an upgrade target based on the most recent and
second most recent major versions and suggests a vulnerability-free release by
leveraging :func:`utils.VersionSuggester.find_latest_safe_version_for_major`.
Additional community activity metrics are obtained through
``utils.CommunityActivityUtils`` and included in the final report.

The output CSV is named ``OutdatedPackageAnalysis_YYYYMMDD.csv`` and contains
the following columns:

``Package Name``
    Package identifier as listed in the requirements file.

``Current Version``
    The pinned version from ``requirements_full_list.txt``.

``Is Major/Second Major Version``
    Indicates whether the upgrade recommendation targets the latest major
    release or the second latest major release available on PyPI.

``Upgrade Available?``
    ``Yes`` when a newer release exists on PyPI, ``No`` otherwise.

``Upgrade Instruction``
    Recommended upgrade action, including the suggested vulnerability-free
    version or an explanatory note when no safe release is available.

``Last Active Date for current major version`` and ``Last active date for
package``
    Activity timestamps obtained from :mod:`utils.CommunityActivityUtils`.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from packaging.version import InvalidVersion, Version

from utils.CommunityActivityUtils import get_activity_dates
from utils.ConfigUtils import parse_requirements
from utils.PyPiUtils import GetPyPiInfo
from utils.SGTUtils import SGTFormatter
from utils.VersionSuggester import find_latest_safe_version_for_major


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(
    SGTFormatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
)
logger.addHandler(handler)
logger.propagate = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class PackageReport:
    """Container for CSV row information."""

    name: str
    current_version: str
    target_major_label: str
    upgrade_available: str
    upgrade_instruction: str
    last_active_current_major: str
    last_active_package: str

    def to_row(self) -> list[str]:
        return [
            self.name,
            self.current_version,
            self.target_major_label,
            self.upgrade_available,
            self.upgrade_instruction,
            self.last_active_current_major,
            self.last_active_package,
        ]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _parse_versions(releases: Iterable[str]) -> list[tuple[Version, str]]:
    """Return sorted ``Version`` objects paired with their original string."""

    parsed: list[tuple[Version, str]] = []
    for ver_str in releases:
        try:
            parsed.append((Version(ver_str), ver_str))
        except InvalidVersion:
            logger.debug("Skipping invalid version string: %s", ver_str)
            continue

    parsed.sort(key=lambda item: item[0])
    return parsed


def _determine_target_major(
    available_versions: list[tuple[Version, str]],
    current_version: Version | None,
) -> tuple[int | None, str, int | None]:
    """Identify the major version that should be evaluated for upgrades.

    Returns a tuple ``(target_major, label, latest_major)`` where ``label`` is a
    human readable description used in the CSV output.  ``target_major`` may be
    ``None`` when no meaningful upgrade target exists.
    """

    if not available_versions:
        return None, "N/A", None

    majors = sorted({parsed.major for parsed, _ in available_versions})
    latest_major = majors[-1]
    second_latest_major = majors[-2] if len(majors) >= 2 else None

    if current_version and current_version.major == latest_major:
        return latest_major, "Latest Major", latest_major

    if second_latest_major is not None:
        return second_latest_major, "Second Latest Major", latest_major

    if current_version is not None:
        return current_version.major, "Current Major", latest_major

    return latest_major, "Latest Major", latest_major


def _has_upgrade(
    available_versions: list[tuple[Version, str]],
    current_version: Version | None,
    current_version_str: str,
) -> tuple[bool, Version | None]:
    """Return whether a newer release exists and the latest version."""

    if not available_versions:
        return False, None

    latest_version = available_versions[-1][0]

    if current_version is None:
        return available_versions[-1][1] != current_version_str, latest_version

    return latest_version > current_version, latest_version


async def _evaluate_package(
    name: str,
    current_version_str: str,
    available_versions: list[tuple[Version, str]],
    target_major: int | None,
    latest_major: int | None,
) -> tuple[str, str]:
    """Return upgrade label and instruction for the package."""

    if target_major is None:
        return "No", "Unable to determine upgrade target"

    version_strings = [ver_str for _, ver_str in available_versions]

    safe_version = await find_latest_safe_version_for_major(
        name,
        current_version_str,
        version_strings,
        target_major,
    )

    if safe_version:
        try:
            safe_parsed = Version(safe_version)
            current_parsed = Version(current_version_str)
            if safe_parsed == current_parsed:
                instruction = (
                    f"Current version {current_version_str} is already the latest "
                    f"safe release within major {target_major}"
                )
            else:
                instruction = f"Upgrade to {safe_version} (major {target_major})"
        except InvalidVersion:
            instruction = f"Upgrade to {safe_version} (major {target_major})"
        return "Yes", instruction

    if latest_major is not None and target_major != latest_major:
        return (
            "Yes",
            f"No vulnerability-free release found for major {target_major}; "
            f"evaluate major {latest_major} instead",
        )

    return "Yes", f"No vulnerability-free release found for major {target_major}"


async def _process_package(
    package: str,
    current_version_str: str,
) -> PackageReport | None:
    """Inspect a single package and generate a report entry when outdated."""

    info = GetPyPiInfo(package)
    if not info:
        logger.warning("PyPI metadata unavailable for %s; skipping", package)
        return None

    releases = info.get("releases", {}) or {}
    parsed_versions = _parse_versions(releases.keys())

    try:
        current_version = Version(current_version_str)
    except InvalidVersion:
        current_version = None
        logger.debug("Invalid current version for %s: %s", package, current_version_str)

    upgrade_available, latest_version = _has_upgrade(
        parsed_versions, current_version, current_version_str
    )

    if not upgrade_available:
        return None

    target_major, major_label, latest_major = _determine_target_major(
        parsed_versions, current_version
    )

    # Ensure that an upgrade exists within the evaluated major when it matches
    # the current major.  If none exists we still call the vulnerability check
    # so that the instruction explains the situation.
    upgrade_flag, instruction = await _evaluate_package(
        package,
        current_version_str,
        parsed_versions,
        target_major,
        latest_major,
    )

    last_active_current_major, last_active_package = get_activity_dates(
        package, current_version_str, info
    )

    return PackageReport(
        name=package,
        current_version=current_version_str,
        target_major_label=major_label,
        upgrade_available=upgrade_flag,
        upgrade_instruction=instruction,
        last_active_current_major=last_active_current_major,
        last_active_package=last_active_package,
    )


async def _generate_reports(
    packages: list[tuple[str, str]],
) -> list[PackageReport]:
    """Process packages sequentially and collect report rows."""

    results: list[PackageReport] = []
    total = len(packages)
    for idx, (name, version_str) in enumerate(packages, start=1):
        logger.info("[%d/%d] Evaluating %s==%s", idx, total, name, version_str)
        report = await _process_package(name, version_str)
        if report:
            results.append(report)
    return results


def _write_csv(rows: list[PackageReport], output_path: Path) -> None:
    """Persist report rows to ``output_path``."""

    header = [
        "Package Name",
        "Current Version",
        "Is Major/Second Major Version",
        "Upgrade Available?",
        "Upgrade Instruction",
        "Last Active Date for current major version",
        "Last active date for package",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row.to_row())


def _resolve_requirements(path: str | None) -> Path:
    """Return the resolved requirements file path."""

    if path:
        candidate = Path(path)
    else:
        candidate = Path("src") / "requirements_full_list.txt"

    if not candidate.exists():
        raise FileNotFoundError(f"Requirements file not found: {candidate}")

    return candidate


def _select_packages(
    requirements_path: Path,
    limit: int | None,
) -> list[tuple[str, str]]:
    """Load packages from the requirements file and apply an optional limit."""

    parsed = parse_requirements(str(requirements_path))
    items = list(parsed.items())
    if limit is not None and limit >= 0:
        return items[:limit]
    return items


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments for the script."""

    parser = argparse.ArgumentParser(
        description="Generate a report for outdated Python packages",
    )
    parser.add_argument(
        "--requirements",
        dest="requirements",
        help="Path to requirements_full_list.txt (default: src/requirements_full_list.txt)",
    )
    parser.add_argument(
        "--output",
        dest="output",
        help="Optional output CSV path. Defaults to OutdatedPackageAnalysis_YYYYMMDD.csv",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N packages from the requirements file",
    )
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> Path:
    """Asynchronous entry point for report generation."""

    requirements_path = _resolve_requirements(args.requirements)
    packages = _select_packages(requirements_path, args.limit)

    if not packages:
        logger.warning("No packages found in %s", requirements_path)
        output_path = Path(args.output) if args.output else Path(
            f"OutdatedPackageAnalysis_{datetime.now():%Y%m%d}.csv"
        )
        _write_csv([], output_path)
        return output_path

    reports = await _generate_reports(packages)

    output_path = (
        Path(args.output)
        if args.output
        else Path(f"OutdatedPackageAnalysis_{datetime.now():%Y%m%d}.csv")
    )
    _write_csv(reports, output_path)
    logger.info("Report written to %s", output_path)
    return output_path


def main() -> None:
    """Command-line entry point."""

    args = parse_arguments()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()

