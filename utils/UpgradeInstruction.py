#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate upgrade instructions for a base package to a specific version,
including compatible and secure dependency versions.
"""
import asyncio
import aiohttp
import logging
import os
from logging import StreamHandler, Formatter
from packaging.requirements import Requirement
from utils.PyPiUtils import GetPyPiInfo
from utils.VersionSuggester import suggest_safe_minor_upgrade, get_all_versions
from utils.VulnChecker import fetch_osv
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from utils.SGTUtils import SGTFormatter
from utils.ConfigUtils import parse_requirements
from dotenv import load_dotenv
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

# cache of current package versions from requirements file
_CURRENT_VERSIONS: dict[str, str] = {}


def _load_current_versions() -> dict[str, str]:
    """Load current package versions from the requirements file."""
    if not _CURRENT_VERSIONS:
        load_dotenv(dotenv_path=".env")
        req_file = os.getenv("REQUIREMENTS_FILE", "src/requirements_full_list.txt")
        try:
            mapping = parse_requirements(req_file)
            _CURRENT_VERSIONS.update({k.lower(): v for k, v in mapping.items()})
        except FileNotFoundError:
            logger.warning(f"Requirements file not found: {req_file}")
        except Exception as e:  # pragma: no cover - robustness
            logger.warning(f"Failed to parse requirements from {req_file}: {e}")
    return _CURRENT_VERSIONS

def _extract_min_version(req: Requirement) -> str | None:
    """
    Return the minimal version that satisfies the requirement specifier.

    Rules
    -----
    1. If the requirement is pinned exactly (== or ===), return that version.
    2. Otherwise, pick the lowest version that appears in any >=, > or ~= bound.
    3. If no lower-bound specifier exists (e.g. just 'requests'), return None.

    Parameters
    ----------
    req : packaging.requirements.Requirement
        Parsed requirement object (already `Requirement(dep)` in your code).

    Returns
    -------
    str | None
        Minimal version as a string (e.g. "1.19.0") or None if not applicable.
    """
    if not req.specifier:
        return None

    min_version: str | None = None

    for spec in req.specifier:
        op, ver = spec.operator, spec.version
        try:
            ver_obj = Version(ver)
        except InvalidVersion:
            # Skip weird / local versions that Version() cannot parse
            continue

        # Case 1 – exact pin wins immediately
        if op in ("==", "==="):
            return ver

        # Case 2 – lower-bound candidates
        if op in (">=", ">", "~="):
            if min_version is None or ver_obj < Version(min_version):
                min_version = ver

    return min_version

async def _latest_safe_version(pkg: str,
                               all_versions: list[str],
                               session: aiohttp.ClientSession,
                               sem: asyncio.Semaphore) -> str | None:
    """
    Return the newest (highest) version that has **no** known vulnerabilities.
    If every version is vulnerable (or an error occurs), return None.
    """
    from packaging.version import Version

    # newest → oldest
    for ver in sorted(all_versions, key=Version, reverse=True):
        try:
            _, status, _ = await fetch_osv(session, pkg, ver, sem)
            if status == "No":
                return ver
        except Exception:
            # network / API hiccup – try older versions
            continue
    return None


async def get_safe_dependency_versions(dependencies: list[str]) -> dict[str, str | None]:
    """
    For each dependency requirement, return a safe (non-vulnerable) version.
    Keys are package names; values are version strings or None.
    """
    results: dict[str, str | None] = {}

    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(10)
        tasks = []

        for dep in dependencies:
            try:
                req = Requirement(dep)
                name = req.name
                all_versions = get_all_versions(name)
                min_ver = _extract_min_version(req)

                # decide which strategy to use
                if min_ver:
                    task = suggest_safe_minor_upgrade(
                        pkg=name,
                        current_version=min_ver,
                        all_versions=all_versions,
                    )
                else:
                    task = _latest_safe_version(name, all_versions, session, sem)

                tasks.append(task)
                results[name] = None        # placeholder
            except Exception as e:
                logger.warning(f"Failed to schedule version check for {dep}: {e}")

        SafeVersions = await asyncio.gather(*tasks, return_exceptions=True)

        # fill in real values
        for (PkgName, safe) in zip(results.keys(), SafeVersions):
            if isinstance(safe, Exception) or safe in (None, "Up-to-date"):
                continue
            results[PkgName] = safe

    return results

def generate_upgrade_instruction(base_package: str, target_version: str) -> dict:
    """
    Generate a detailed upgrade instruction including secure dependencies.
    """
    pypi = GetPyPiInfo(base_package)
    if not pypi:
        raise ValueError(f"Failed to fetch PyPI metadata for {base_package}")

    releases = pypi.get("releases", {})
    if target_version not in releases:
        raise ValueError(f"Target version {target_version} not found for {base_package}")

    requires_dist = pypi.get("info", {}).get("requires_dist") or []
    # logger.info(f"{base_package}=={target_version} requires: {requires_dist}")

    # Use asyncio.run to avoid 'event loop already running' issues
    SafeVersions = asyncio.run(get_safe_dependency_versions(requires_dist))
    current_versions = _load_current_versions()

    dependencies: list[str] = []
    for dep in requires_dist:
        try:
            req = Requirement(dep)
        except Exception as e:  # pragma: no cover - unexpected formats
            logger.warning(f"Failed to parse dependency {dep}: {e}")
            continue

        cur = current_versions.get(req.name.lower())
        if cur:
            try:
                if req.specifier.contains(Version(cur), prereleases=True):
                    # already within required range; skip
                    continue
            except InvalidVersion:
                pass

        safe = SafeVersions.get(req.name)
        if safe:
            dependencies.append(f"{req.name}=={safe}")

    instruction = {
        "base_package": f"{base_package}=={target_version}",
        "dependencies": dependencies,
    }
    return instruction

def _is_version_satisfied(req: Requirement, current_version: str) -> bool:
    """Check if current version satisfies the requirement."""
    try:
        return req.specifier.contains(Version(current_version), prereleases=True)
    except InvalidVersion:
        logger.debug(f"Invalid version format: {current_version}")
        return False

def generate_current_dependency_json(base_package: str,
                                     current_version: str,
                                     requires_dist: list[str]) -> dict:
    """Return current version info with dependency versions."""
    dependencies: list[str] = []
    for dep in requires_dist:
        try:
            req = Requirement(dep)
            pkg_name = req.name.lower()
            
            # Check if we should skip this dependency
            current_version = current_versions.get(pkg_name)
            if current_version and _is_version_satisfied(req, current_version):
                logger.debug(f"Skipping {req.name}: current version {current_version} satisfies requirement")
                continue
                
            # Add safe version if available
            safe_version = SafeVersions.get(req.name)
            if safe_version:
                dependencies.append(f"{req.name}=={safe_version}")
                
        except Exception as e:  # pragma: no cover - unexpected formats
            logger.warning(f"Failed to process dependency {dep}: {e}")

    return {
        "base_package": f"{base_package}=={current_version}",
        "dependencies": deps,
    }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate secure upgrade instructions")
    parser.add_argument("package", help="Base package name")
    parser.add_argument("version", help="Target version")
    args = parser.parse_args()

    result = generate_upgrade_instruction(args.package, args.version)
    print("Upgrade Instruction:")
    print(result)
