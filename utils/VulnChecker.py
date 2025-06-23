#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vulnerability checking utilities for Python packages via OSV API.
Contains functions to check vulnerabilities for a specific version
or multiple versions asynchronously.
"""

import asyncio
import aiohttp
import logging
from logging import StreamHandler, Formatter
from datetime import datetime
from utils.SGTUtils import SGTFormatter
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

async def fetch_osv(session: aiohttp.ClientSession, package: str, ver: str,
                    sem: asyncio.Semaphore, retry: int = 3) -> tuple:
    """
    Asynchronously query osv.dev for vulnerabilities on a specific package version.

    Args:
        session (aiohttp.ClientSession): Reusable HTTP session.
        package (str): Name of the package.
        ver (str): Version string to check.
        sem (asyncio.Semaphore): Semaphore object to limit concurrency.
        retry (int): Number of retries upon failure (default: 3).

    Returns:
        tuple: (version (str), status (str), details (str))
            - status: 'Yes', 'No', or 'unknown'
            - details: Summary text or empty string
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        },
        "version": ver
    }
    for attempt in range(retry):
        try:
            async with sem:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 200:
                        data = await r.json()
                        vulns = data.get('vulns', [])
                        if not vulns:
                            return ver, 'No', ''
                        details = []
                        for v in vulns:
                            aliases = v.get('aliases', [])
                            vuln_id = next((a for a in aliases if a.startswith("CVE-")), v.get('id', ''))
                            summary = v.get('summary', '')
                            severity = 'UNKNOWN'
                            score = ''

                            if 'severity' in v and v['severity']:
                                s = v['severity'][0]
                                severity = s.get('type', 'UNKNOWN')
                                score = s.get('score', '')
                            elif 'cvss' in v.get('database_specific', {}):
                                cvss = v['database_specific']['cvss']
                                severity = cvss.get('severity', 'UNKNOWN')
                                score = str(cvss.get('score', ''))

                            # Parse affected version ranges
                            affected_versions = set()
                            for aff in v.get('affected', []):
                                version_ranges = []
                                for r in aff.get('ranges', []):
                                    if r.get('type') == 'ECOSYSTEM':
                                        for evt in r.get('events', []):
                                            if 'introduced' in evt:
                                                version_ranges.append(f">={evt['introduced']}")
                                            if 'fixed' in evt:
                                                version_ranges.append(f"<{evt['fixed']}")
                                if version_ranges:
                                    affected_versions.add(','.join(version_ranges))

                            affected_str = '; '.join(affected_versions) or 'unknown'

                            details.append(f"{vuln_id}, {severity}, {summary}, {score}, affects: {affected_str}")
                        
                        return ver, 'Yes', '\n'.join(details)
        except Exception as e:
            logger.warning(f"[async] OSV check failed for {package}=={ver}: {repr(e)}")
    return ver, 'unknown', ''

async def check_multiple_versions(
    package: str,
    versions: list,
    smp_num: int,
    session: aiohttp.ClientSession = None,
    shared_sem: asyncio.Semaphore = None
) -> dict:
    """
    Perform asynchronous OSV vulnerability checks on multiple versions of a package.

    Args:
        package (str): Package name to check.
        versions (list): List of version strings to scan.
        smp_num (int): Maximum concurrency allowed for scanning.
        session (aiohttp.ClientSession, optional): Shared aiohttp session. Will create a new one if not provided.
        shared_sem (asyncio.Semaphore, optional): Shared semaphore to control concurrency. Will create a new one if not provided.

    Returns:
        dict: Mapping from version string to (vulnerable_flag, details) tuple.
              Example: {"1.2.3": ("Yes", "CVE-2022-xxxx ..."), "1.2.4": ("No", "")}
    """
    results = {}
    sem = shared_sem or asyncio.Semaphore(smp_num)
    owns_session = session is None

    if owns_session:
        session = aiohttp.ClientSession()

    try:
        tasks = [fetch_osv(session, package, v, sem) for v in versions]
        for coro in asyncio.as_completed(tasks):
            ver, flag, details = await coro
            results[ver] = (flag, details)
    finally:
        if owns_session:
            await session.close()

    return results

async def check_cv_uv(pkg: str, cur_ver: str, newer: list, smp_num: int):
    """
    Asynchronously check both current and upgrade version vulnerabilities.

    This function runs two vulnerability scans in parallel:
    - One for the current installed version of a package
    - One for all newer available versions (potential upgrades)

    It shares the same aiohttp session and semaphore to optimize HTTP usage.

    Args:
        pkg (str): Name of the package.
        cur_ver (str): Current installed version.
        newer (list): List of newer version strings to check.
        smp_num (int): Maximum concurrency allowed for async tasks.

    Returns:
        tuple:
            - current_result (tuple): (version, status, details) for current version
            - upgrade_results (dict): version -> (status, details) mapping for upgrade candidates
    """
    sem = asyncio.Semaphore(smp_num)
    async with aiohttp.ClientSession() as session:
        current_task = fetch_osv(session, pkg, cur_ver, sem)
        upgrade_task = check_multiple_versions(pkg, newer, smp_num, session=session, shared_sem=sem)
        return await asyncio.gather(current_task, upgrade_task)

def main() -> None:
    import argparse
    logging.basicConfig(level=logging.WARNING)

    parser = argparse.ArgumentParser(description="Check vulnerabilities for a given package version")
    parser.add_argument("package", help="Package name to check")
    parser.add_argument("version", help="Package version to check")
    parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent checks")
    args = parser.parse_args()

    async def run():
        sem = asyncio.Semaphore(args.concurrency)
        async with aiohttp.ClientSession() as session:
            ver, status, details = await fetch_osv(session, args.package, args.version, sem)
            print(f"Package: {args.package}=={args.version}")
            print(f"Vulnerable: {status}")
            if details:
                print("Details:")
                print(details)

    asyncio.run(run())


if __name__ == "__main__":
    main()
