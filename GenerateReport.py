#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Weekly vulnerability and upgrade report generator for Python packages.
Scans for known vulnerabilities using pip-audit and OSV, gathers PyPI metadata,
and outputs detailed weekly reports in CSV, HTML, and JSON formats.
"""
import os
import sys
import csv
import json
import logging
import shlex
import argparse
import asyncio
from dotenv import load_dotenv
from datetime import datetime
from logging import StreamHandler, Formatter
from packaging import version
from packaging.version import InvalidVersion
from jinja2 import Environment, FileSystemLoader
from utils.ConfigUtils import(
    get_report_paths,
    get_report_output_folder,
    load_base_packages,
    parse_requirements
)
from utils.CustodianUtils import(
    load_custodian_map,
    decode_base64_env,
    custom_sort_key
)
from utils.PyPiUtils import (
    GetPyPiInfo
)
from utils.VersionSuggester import (
    suggest_safe_minor_upgrade
)
from utils.VulnChecker import (
    check_cv_uv
)
from utils.SGTUtils import (
    SGTFormatter,
    now_sg
)
from utils.UpgradeInstruction import generate_upgrade_instruction

# ---------------- Configuration ----------------
# Load environment variables from .env file
load_dotenv(dotenv_path=".env")

FULL_RELOAD_PACKAGES = os.getenv("FULL_RELOAD_PACKAGES", "False").lower() == "true"
BASE_PACKAGE_TXT = os.getenv("BASE_PACKAGE_TXT", "src/base_package_list.txt")
BASE_PACKAGE_CSV = os.getenv("BASE_PACKAGE_CSV", "src/BasePackageWithDependencies.csv")
CHECK_DEPENDENCY_SCRIPT = os.getenv("CHECK_DEPENDENCY_SCRIPT", "utils/CheckDependency.py")
REQUIREMENTS_FILE = os.getenv("REQUIREMENTS_FILE", "src/requirements_full_list.txt")
CUSTODIAN_LIST = os.getenv("CUSTODIAN_LIST", "src/custodian.csv")
NOTUSED_PACKAGES = os.getenv("NOTUSED_PACKAGES", "src/NotUsed.txt")
PIP_AUDIT_CMD = shlex.split(os.getenv("PIP_AUDIT_CMD", "pip-audit --format json"))
SEMAPHORE_NUMBER = int(os.getenv("SEMAPHORE_NUMBER", 3))
failed_versions = []

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger
# ---------------- Utility Functions ----------------
def main() -> None:
    """
    Main entry point for generate weekly report workflow.

    - Parses the requirements file.
    - Fetches metadata and known vulnerabilities.
    - Suggests upgrades and gathers dependency info.
    - Outputs reports in selected formats (CSV, HTML, JSON).

    Returns:
        None
    """
    paths = get_report_paths()
    report_dir = get_report_output_folder()
    monthly_report_dir = get_monthly_report_output_folder()

    OUTPUT_CSV = paths["csv"]
    logger.debug(f"CSV Path: {OUTPUT_CSV}")
    OUTPUT_HTML = paths["html"]
    logger.debug(f"HTML Path: {OUTPUT_HTML}")
    OUTPUT_JSON = paths["json"]
    logger.debug(f"JSON Path: {OUTPUT_JSON}")
    OUTPUT_FAILED = paths["failed"]
    logger.debug(f"Failed Package Path: {OUTPUT_FAILED}")

    parser = argparse.ArgumentParser(description="Dependency vulnerability scanner")
    parser.add_argument('--output', nargs='+', choices=['csv', 'html', 'json', 'all'], default=['all'],
                        help="Choose one or more output formats (e.g. --output csv html)")
    args = parser.parse_args()

    # Read NotUsed.txt
    try:
        with open("./src/NotUsed.txt", "r") as f:
            NotUsedPackages = set(line.strip().lower() for line in f if line.strip())
        logger.info(f"Loaded {len(NotUsedPackages)} packages from NotUsed.txt")
    except FileNotFoundError:
        logger.warning("NotUsed.txt not found.")
        NotUsedPackages = set()

    # Load package list need to processed
    pkgs = parse_requirements(REQUIREMENTS_FILE)
    # Load base package list
    base_packages = load_base_packages()

    # Load Custodian Mapping
    CUSTODIAN_MAP = {
    "1": decode_base64_env("CUSTODIAN_1"),
    "2": decode_base64_env("CUSTODIAN_2")
    }
    custodian_ordering = {v: i for i, v in enumerate(CUSTODIAN_MAP.values())}
    raw_custodian_map = load_custodian_map(CUSTODIAN_LIST)
    logger.debug(f"Raw Custodian Map Output: \n {raw_custodian_map}")

    # Remap raw_custodian_map to decoded mapping
    custodian_map = {}
    for pkg_name, (cust_id, pkg_type) in raw_custodian_map.items():
        decoded = CUSTODIAN_MAP.get(str(cust_id), cust_id)
        custodian_map[pkg_name.lower()] = (decoded, pkg_type)
    logger.debug(f"Decoded Custodian Map Output: \n {custodian_map}")

    # Initialize final output row
    rows = []
    for idx, (pkg, cur_ver) in enumerate(pkgs.items(), 1):
        logger.info(f"[{idx}/{len(pkgs)}] Processing package: {pkg}, current version: {cur_ver}")

        info = GetPyPiInfo(pkg)
        logger.debug(f"Info detail: \n{info}")
        if info:
            # Filter out invalid versions before sorting
            raw_versions = info.get('releases', {}).keys()
            logger.debug(f"Raw versions: \n{raw_versions}")
            valid_versions = []
            for v in raw_versions:
                try:
                    parsed_v = version.parse(v)
                    valid_versions.append(v)
                except InvalidVersion:
                    logger.warning(f"Package {pkg} has invalid version string skipped: {v}")

            all_vs = sorted(valid_versions, key=version.parse)

            cur_ver_deps = []
            release_info = info.get('releases', {}).get(cur_ver, [])
            logger.debug(f"Release info: \n{release_info}")
            if release_info:
                for entry in release_info:
                    if 'requires_dist' in entry:
                        logger.debug(f"requires_dist: \n{requires_dist}")
                        cur_ver_deps.extend(entry['requires_dist'])
                        break
            if not cur_ver_deps:
                cur_ver_deps = info.get('info', {}).get('requires_dist') or []

        else:
            all_vs = []

        try:
            newer = [v for v in all_vs if version.parse(v) > version.parse(cur_ver)]
        except InvalidVersion:
            logger.error(f"InvalidVersion: Cannot parse current version '{cur_ver}' for package {pkg}")
            newer = []
        latest = all_vs[-1] if all_vs else 'unknown'

        deps = info.get('info', {}).get('requires_dist') or []

        suggested = asyncio.run(
            suggest_safe_minor_upgrade(pkg, cur_ver, all_vs)
        )

        # run both current + upgrade checks in parallel
        (cv_ver, cv_status, cv_details), upgrade_vuln_map = asyncio.run(
            check_cv_uv(pkg, cur_ver, newer, SEMAPHORE_NUMBER)
        )

        # aggregate
        upgrade_vuln = 'Yes' if any(v[0] == 'Yes' for v in upgrade_vuln_map.values()) else 'No'
        upgrade_vuln_details = '; '.join(
            f"{ver}: {details}" for ver, (flag, details) in upgrade_vuln_map.items() if flag == 'Yes'
        ) or 'None'

        # Get custodian
        custodian, _ = custodian_map.get(pkg.lower(), ("Unknown", "Dependency Package"))

        # Get Upgrade Instruction
        if suggested in ("unknown", "Up-to-date"):
            instruction = {"base_package": f"{pkg}=={version}", "dependencies": []}
        else:
            instruction = generate_upgrade_instruction(pkg, suggested)

        # Mark for Not Used Packages
        Remarks = "Not Used" if pkg.lower() in NotUsedPackages else ""

        rows.append({
            'Package Name': pkg,
            'Package Type': 'Base Package' if pkg.lower() in base_packages else 'Dependency Package',
            'Custodian': custodian,
            'Current Version': cur_ver,
            'Dependencies for Current': '; '.join(cur_ver_deps),
            # 'All Available Versions': ', '.join(all_vs),
            'Newer Versions': ', '.join(newer),
            'Dependencies for Latest': '; '.join(deps),
            'Latest Version': latest,
            'Current Version Vulnerable?': cv_status,
            'Current Version Vulnerability Details': cv_details,
            'Upgrade Version Vulnerable?': upgrade_vuln,
            'Upgrade Vulnerability Details': upgrade_vuln_details,
            'Suggested Upgrade': suggested,
            'Upgrade Instruction': instruction,
            'Remarks': Remarks
        })
        logger.debug(f"Custodian for {pkg}: {custodian}")
        logger.debug(f"Current Version for {pkg}: {cur_ver}")
        logger.debug(f"Suggested Version for {pkg}: {suggested}")
        logger.debug(f"Current Version vulnerable for {pkg}: {cv_status}")

    # Sort output with specific order
    rows.sort(key=lambda row: custom_sort_key(row, custodian_ordering))

    # write output
    fieldnames = list(rows[0].keys()) if rows else []
    output_set = set(args.output)
    if 'all' in output_set:
        output_set = {'csv', 'html', 'json'}

    if 'csv' in output_set:
        try:
            with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            print(f"✅ CSV report saved to {OUTPUT_CSV}")
        except Exception as e:
            print(f"❌ Failed to write CSV: {e}")

    if 'html' in output_set:
        try:
            env = Environment(loader=FileSystemLoader('templates'))
            template = env.get_template('weekly_report.html.j2')
            html = template.render(
                headers=fieldnames,
                rows=rows,
                generated_at=now_sg().strftime("%Y-%m-%d %H:%M:%S %Z")
            )

            with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"✅ HTML report saved to {OUTPUT_HTML}")
        except Exception as e:
            print(f"❌ Failed to write HTML: {e}")

    if 'json' in output_set:
        try:
            with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
                json.dump(rows, jf, indent=2, ensure_ascii=False)
            print(f"✅ JSON report saved to {OUTPUT_JSON}")
        except Exception as e:
            print(f"❌ Failed to write JSON: {e}")

    if failed_versions:
        try:
            with open(OUTPUT_FAILED, 'w') as f:
                f.write('\n'.join(failed_versions))
            logger.warning(f"⚠️ {len(failed_versions)} package versions failed vulnerability check. Saved to {OUTPUT_FAILED}.txt")
        except Exception as e:
            print(f"❌ Failed to write failed packages list: {e}")

    # Monthly Report
    import pandas as pd
    from datetime import datetime
    monthly_df = pd.DataFrame(rows)[[
        'Package Name', 'Package Type', 'Custodian', 'Current Version',
        'Dependencies for Current', 'Newer Versions', 'Dependencies for Latest',
        'Latest Version', 'Current Version Vulnerable?', 'Current Version Vulnerability Details',
        'Upgrade Version Vulnerable?', 'Upgrade Vulnerability Details',
        'Suggested Upgrade', 'Remarks'
    ]]
    # Overview Sheet
    total_packages = len(monthly_df)
    base_count = (monthly_df['Package Type'] == 'Base Package').sum()
    dep_count = total_packages - base_count
    custodian_summary = monthly_df.groupby(['Custodian', 'Package Type']).size().unstack(fill_value=0)
    custodian_summary['Total'] = custodian_summary.sum(axis=1)
    overview_df = pd.DataFrame({
        "Metric": ["Total Packages", "Base Packages", "Dependency Packages"],
        "Count": [total_packages, base_count, dep_count]
    })
    # Custodian Sheet
    custodian_raw_df = pd.read_csv(CUSTODIAN_LIST)
    custodian_map_rev = {
        "1": decode_base64_env("CUSTODIAN_1"),
        "2": decode_base64_env("CUSTODIAN_2")
    }
    custodian_raw_df['Custodian'] = custodian_raw_df['Custodian'].astype(str).map(custodian_map_rev)

    now = datetime.now().strftime("%Y%m-%d-%H%M")
    monthly_file_path = os.path.join(monthly_report_dir, f"MonthlyReport-{now}.xlsx")
    YearMonth = datetime.now().strftime("%Y%m")

    # Write to Monthly Report
    try:
        with pd.ExcelWriter(monthly_file_path, engine='xlsxwriter') as writer:
            overview_df.to_excel(writer, sheet_name='Overview', index=False)
            custodian_summary.reset_index().to_excel(writer, sheet_name='Overview', startrow=5, index=False)
            custodian_raw_df.to_excel(writer, sheet_name='Custodian', index=False)
            monthly_df.to_excel(writer, sheet_name=f'Monthly Report - {YearMonth}', index=False)
        print(f"\U0001F4C4 Monthly Excel report saved to {monthly_file_path}")
    except Exception as e:
        print(f"\u274C Failed to write monthly Excel report: {e}")

    # Summary logging
    total = len(rows)
    base_count = sum(1 for r in rows if r['Package Type'] == 'Base Package')
    dep_count = total - base_count

    base_vuln = sum(1 for r in rows if r['Package Type'] == 'Base Package' and r['Current Version Vulnerable?'] == 'Yes')
    dep_vuln = sum(1 for r in rows if r['Package Type'] == 'Dependency Package' and r['Current Version Vulnerable?'] == 'Yes')

    logger.info("📦 Weekly Report Summary")
    logger.info(f"🔍 Total packages scanned: {total} (Base: {base_count}, Dependency: {dep_count})")
    logger.info(f"🚨 Vulnerabilities found in current versions:")
    logger.info(f"   • Base packages: {base_vuln} / {base_count}")
    logger.info(f"   • Dependency packages: {dep_vuln} / {dep_count}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Execution interrupted by user.")
        sys.exit(1)
