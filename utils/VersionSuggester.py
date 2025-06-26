#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suggest upgrade versions for a Python package.
"""
import aiohttp
import asyncio
import utils
from packaging import version
import requests
import argparse
import logging
from packaging.version import InvalidVersion
from logging import StreamHandler, Formatter
from datetime import datetime
from utils.SGTUtils import SGTFormatter
from utils.VulnChecker import fetch_osv
# from utils.GenerateReport_Archive import suggest_upgrade_version
# Custom formatter (assumes SGTFormatter is defined elsewhere or should be implemented here)
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from pytz import timezone as ZoneInfo  # for Python <3.9

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger

PYPI_URL = "https://pypi.org/pypi/{package}/json"

def get_all_versions(pkg: str) -> list:
    """
    Fetch all release versions from PyPI.
    """
    r = requests.get(PYPI_URL.format(package=pkg), timeout=5)
    r.raise_for_status()
    data = r.json()
    return [v for v in data.get("releases", {})]

def suggest_upgrade_version(all_versions: list, current_version: str) -> str:
    """Suggest the best upgrade version from ``all_versions``.

    Preference is given to the newest version within the same major
    release.  If none is newer in the same major version, the absolute
    newest version is returned.  ``Up-to-date`` is returned when no
    newer release exists.
    """
    try:
        cur_ver = version.parse(current_version)
        parsed_versions = []
        for v in all_versions:
            try:
                pv = version.parse(v)
                parsed_versions.append((pv, v))
            except InvalidVersion:
                continue

        newer_versions = [v for (pv, v) in parsed_versions if pv > cur_ver]
        if not newer_versions:
            return "Up-to-date"

        same_major = [v for (pv, v) in parsed_versions
                      if pv > cur_ver and pv.major == cur_ver.major]
        if same_major:
            return same_major[-1]

        return newer_versions[-1]
    except Exception as e:
        logger.error(f"Suggest upgrade error for {current_version}: {e}")
        return "unknown"

async def suggest_safe_minor_upgrade(
    pkg: str, current_version: str, all_versions: list
) -> str:
    """Return the safest upgrade version within the same major release.

    If all minor versions are vulnerable, try the next major release and
    return its newest non-vulnerable version.  ``Up-to-date`` is returned
    when no higher secure version is found.
    """

    try:
        cur_ver = version.parse(current_version)

        minor_candidates: list[tuple[version.Version, str]] = []
        higher_major: list[tuple[version.Version, str]] = []

        for v in all_versions:
            try:
                pv = version.parse(v)
            except InvalidVersion:
                continue

            if pv < cur_ver:
                continue

            if pv.major == cur_ver.major:
                minor_candidates.append((pv, v))
            elif pv.major > cur_ver.major:
                higher_major.append((pv, v))

        # newest first within current major
        minor_candidates.sort(reverse=True, key=lambda x: x[0])

        sem = asyncio.Semaphore(5)
        async with aiohttp.ClientSession() as session:
            for _, ver_str in minor_candidates:
                _, status, _ = await fetch_osv(session, pkg, ver_str, sem)
                if status == "No":
                    return ver_str

            if higher_major:
                next_major = min(pv.major for pv, _ in higher_major)
                next_major_versions = [
                    (pv, v) for pv, v in higher_major if pv.major == next_major
                ]
                next_major_versions.sort(reverse=True, key=lambda x: x[0])

                for _, ver_str in next_major_versions:
                    _, status, _ = await fetch_osv(session, pkg, ver_str, sem)
                    if status == "No":
                        return ver_str

        return "Up-to-date"

    except Exception as e:  # pragma: no cover - network/parse issues
        logger.warning(f"Error in suggest_safe_minor_upgrade: {e}")
        return "unknown"


def main():
    """
    Parses command-line arguments and suggests upgrade versions for a specified Python package.
    
    Fetches all available versions of the given package from PyPI and, if requested, suggests a minor upgrade that is not affected by known vulnerabilities. Intended to be used as the script's entry point.
    """
    parser = argparse.ArgumentParser(description="Suggest upgrade versions")
    parser.add_argument("package", help="Package name on PyPI")
    parser.add_argument("current", help="Current installed version")
    parser.add_argument("--safe-minor", action="store_true",
                        help="Also suggest safe minor upgrade")
    args = parser.parse_args()

    global pkg_name
    pkg_name = args.package  # used in suggest_safe_minor_upgrade

    versions = get_all_versions(pkg_name)
    # basic = suggest_upgrade_version(versions, args.current)
    # print(f"Suggested upgrade: {basic}")

    if args.safe_minor:
        safe = asyncio.run(
            suggest_safe_minor_upgrade(pkg_name, args.current, versions)
        )
        print(f"Safe minor upgrade: {safe}")

if __name__ == "__main__":
    main()
