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
import tempfile
from dotenv import load_dotenv
from datetime import datetime
from logging import StreamHandler, Formatter
from packaging import version
from packaging.version import InvalidVersion
from jinja2 import Environment, FileSystemLoader
from utils.ConfigUtils import(
    get_report_paths,
    get_report_output_folder,
    get_monthly_report_output_folder,
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
from utils.UpgradeInstruction import (
    generate_upgrade_instruction,
    generate_current_dependency_json,
)
from utils.InstructionFormatter import instruction_to_text
from utils.utils import run_py

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
PERSONAL_REPORT_DIR = os.getenv("PERSONAL_REPORT_DIR", "temp/")
os.makedirs(PERSONAL_REPORT_DIR, exist_ok=True)
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
    Generates a comprehensive weekly vulnerability and upgrade report for Python packages.
    
    This function orchestrates the end-to-end workflow for scanning Python dependencies, checking for known vulnerabilities, suggesting safe upgrades, and compiling detailed reports. It parses requirements, fetches PyPI metadata, analyzes dependencies, checks vulnerabilities asynchronously, and aggregates custodian and usage information. Reports are generated in CSV, HTML, JSON, and Excel formats, including specialized personal reports for vulnerable packages. The function also handles monthly summary report creation and enhanced HTML output for email notifications.
    
    The workflow includes:
    - Parsing command-line arguments for output formats and base package list updates.
    - Loading package lists, custodian mappings, and usage status.
    - Gathering metadata, dependency, and vulnerability information for each package.
    - Suggesting upgrades and generating upgrade instructions where applicable.
    - Writing reports in multiple formats and generating summary statistics.
    
    No value is returned.
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
    parser.add_argument('--update-base', action='store_true',
                        help='Regenerate base_package_list.txt using CheckDependency.py before generating report')
    args = parser.parse_args()

    # Update base package list if requested or missing
    if args.update_base or not os.path.exists(BASE_PACKAGE_TXT):
        logger.info("Updating base package list via CheckDependency.py")
        run_py(CHECK_DEPENDENCY_SCRIPT)

    # Read list of packages marked as not used
    try:
        with open(NOTUSED_PACKAGES, "r") as f:
            NotUsedPackages = {
                line.strip().lower() for line in f if line.strip()
            }
        logger.info(
            f"Loaded {len(NotUsedPackages)} packages from {NOTUSED_PACKAGES}"
        )
    except FileNotFoundError:
        logger.warning(f"NotUsed file not found: {NOTUSED_PACKAGES}")
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
                        logger.debug(f"requires_dist: \n{entry['requires_dist']}")
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

        # run both current + upgrade checks in parallel
        (cv_ver, cv_status, cv_details), upgrade_vuln_map = asyncio.run(
            check_cv_uv(pkg, cur_ver, newer, SEMAPHORE_NUMBER)
        )

        # Decide whether upgrade suggestion is needed
        if cv_status == 'No' or (latest != 'unknown' and cur_ver == latest):
            suggested = None
            instruction = None
        else:
            suggested = asyncio.run(
                suggest_safe_minor_upgrade(pkg, cur_ver, all_vs)
            )
            if suggested in (None, "unknown", "Up-to-date") or suggested == cur_ver:
                instruction = None
            else:
                instruction = generate_upgrade_instruction(pkg, suggested)

        # Current version dependency JSON (only for base packages)
        if pkg.lower() in base_packages:
            current_json = generate_current_dependency_json(pkg, cur_ver, cur_ver_deps)
        else:
            current_json = None

        # aggregate
        upgrade_vuln = 'Yes' if any(v[0] == 'Yes' for v in upgrade_vuln_map.values()) else 'No'
        upgrade_vuln_details = '; '.join(
            f"{ver}: {details}" for ver, (flag, details) in upgrade_vuln_map.items() if flag == 'Yes'
        ) or 'None'

        # Get custodian
        custodian, _ = custodian_map.get(pkg.lower(), ("Unknown", "Dependency Package"))

        # Get Upgrade Instruction handled above

        # Mark for Not Used Packages
        Remarks = "Not Used" if pkg.lower() in NotUsedPackages else ""

        rows.append({
            'Package Name': pkg,
            'Package Type': 'Base Package' if pkg.lower() in base_packages else 'Dependency Package',
            'Custodian': custodian,
            'Current Version': cur_ver,
            'Current Version With Dependency JSON': current_json,
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

    now = now_sg()
    timestamp = now.strftime("%Y%m-%d-%H%M")
    monthly_file_path = os.path.join(
        monthly_report_dir, f"MonthlyReport-{timestamp}.xlsx"
    )
    YearMonth = now.strftime("%Y%m")

    # Write to Monthly Report
    try:
        with pd.ExcelWriter(monthly_file_path, engine='xlsxwriter') as writer:
            overview_df.to_excel(writer, sheet_name='Overview', index=False)
            custodian_summary.reset_index().to_excel(writer, sheet_name='Overview', startrow=5, index=False)
            custodian_raw_df.to_excel(writer, sheet_name='Custodian', index=False)
            monthly_df.to_excel(writer, sheet_name=f'Monthly Report - {YearMonth}', index=False)
            # Hide specific columns in Excel
            worksheet = writer.sheets[f'Monthly Report - {YearMonth}']
            col_indices = monthly_df.columns.get_indexer(['Dependencies for Current', 'Dependencies for Latest'])
            for col_idx in col_indices:
                worksheet.set_column(col_idx, col_idx, None, None, {'hidden': True})
        print(f"\U0001F4C4 Monthly Excel report saved to {monthly_file_path}")
    except Exception as e:
        print(f"\u274C Failed to write monthly Excel report: {e}")

    # Personal Report: For email notification report only
    # Filter only vulnerable and not marked as Not Used
    PersonalReportRows = [
        r for r in rows
        if r['Current Version Vulnerable?'] == 'Yes' and "not used" not in r['Remarks'].lower()
    ]

    if PersonalReportRows:
        # Save personal report files
        personal_csv_path = os.path.join(PERSONAL_REPORT_DIR, "PersonalReport.csv")
        personal_html_path = os.path.join(PERSONAL_REPORT_DIR, "PersonalReport.html")
        summary_txt_path = os.path.join(PERSONAL_REPORT_DIR, "PersonalReportSummary.txt")

        # Save PersonalReport.csv
        with open(personal_csv_path, 'w', newline='', encoding='utf-8-sig') as pf:
            writer = csv.DictWriter(pf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(PersonalReportRows)
        print(f"✅ Personal CSV report saved to {personal_csv_path}")

        # Save PersonalReport.html
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('weekly_report.html.j2')
        personal_html = template.render(
            headers=fieldnames,
            rows=PersonalReportRows,
            generated_at=now_sg().strftime("%Y-%m-%d %H:%M:%S %Z")
        )
        with open(personal_html_path, 'w', encoding='utf-8') as f:
            f.write(personal_html)
        print(f"✅ Personal HTML report saved to {personal_html_path}")

        # Save summary info
        with open(summary_txt_path, "w") as f:
            f.write(f"UPGRADE_COUNT={len(PersonalReportRows)}\n")
            f.write("PACKAGE_LIST:\n")
            for row in PersonalReportRows:
                f.write(f"- {row['Package Name']} ({row['Current Version']}) - Custodian: {row['Custodian']}\n")
                instr_text = instruction_to_text(row.get('Upgrade Instruction'))
                if instr_text:
                    f.write(f"  Upgrade Instruction: {instr_text}\n")

        # Save enhanced HTML table for email body with new requirements
        email_html_path = os.path.join(PERSONAL_REPORT_DIR, "PersonalReportEmail.html")
        print(f"🔍 DEBUG: Generating email table with {len(PersonalReportRows)} rows")
        with open(email_html_path, "w", encoding="utf-8") as ef:
            ef.write("<table border='1' cellspacing='0' cellpadding='4'>\n")
            ef.write("<tr><th>S/N</th><th>Custodian</th><th>Base Package</th><th>Dependency Packages</th><th>Vulnerability Details</th></tr>\n")
            
            for idx, row in enumerate(PersonalReportRows, 1):
                print(f"🔍 DEBUG: Processing row {idx}: {row.get('Package Name', 'Unknown')}")
                instr = row.get('Upgrade Instruction') or {}
                custodian = row.get('Custodian', '')
                base_pkg = row.get('Package Name', '')
                cur_ver = row.get('Current Version', '')
                suggested_ver = row.get('Suggested Upgrade', '')
                vuln_details = row.get('Current Version Vulnerability Details', '')
                
                base_instr = instr.get('base_package', '')
                deps = instr.get('dependencies', []) or []

                # Extract target version from base package instruction
                target_ver = ''
                if base_instr:
                    try:
                        _, target_ver = base_instr.split('==', 1)
                    except ValueError:
                        pass

                # Format base package display with current → suggested version
                base_display = f"{base_pkg} ({cur_ver})"
                if target_ver and target_ver != cur_ver:
                    base_display += f" → {target_ver}"
                elif suggested_ver and suggested_ver not in ['Up-to-date', '', 'unknown', None]:
                    base_display += f" → {suggested_ver}"

                # Process dependency packages with reasons and new version requirements
                dependency_rows = []
                if deps:
                    # Get current dependency info for comparison
                    current_deps_json = row.get('Current Version With Dependency JSON', '{}')
                    try:
                        current_deps_data = json.loads(current_deps_json)
                        current_deps = {dep.split('==')[0]: dep.split('==')[1] if '==' in dep else 'unknown'
                                         for dep in current_deps_data.get('dependencies', []) if current_deps_data}
                    except (json.JSONDecodeError, KeyError, AttributeError):
                        current_deps = {}
                    
                    # Get new version dependency requirements
                    new_version_deps = row.get('Dependencies for Latest', '')
                    new_version_deps_list = [dep.strip() for dep in new_version_deps.split(';') if dep.strip()]
                    
                    for dep in deps:
                        dep_name = dep.split('==')[0] if '==' in dep else dep
                        dep_version = dep.split('==')[1] if '==' in dep else 'unknown'
                        current_version = current_deps.get(dep_name, 'unknown')
                        
                        # Find the new version requirement for this dependency
                        new_version_req = "unknown"
                        for new_dep in new_version_deps_list:
                            if new_dep.startswith(f"{dep_name}>=") or new_dep.startswith(f"{dep_name}<") or new_dep.startswith(f"{dep_name}~="):
                                new_version_req = new_dep
                                break
                            elif new_dep.startswith(f"{dep_name}") and "==" not in new_dep:
                                new_version_req = new_dep
                                break
                        
                        # Determine upgrade reason
                        reason = "Dependency requirement change"
                        if current_version != 'unknown' and current_version != dep_version:
                            reason = f"Version upgrade required: {current_version} → {dep_version}"
                        
                        # Enhanced display with new version requirements
                        if new_version_req != "unknown":
                            dependency_rows.append(f"{dep} (Reason: {reason}, New version requires: {new_version_req})")
                        else:
                            dependency_rows.append(f"{dep} (Reason: {reason})")
                else:
                    dependency_rows.append("-")

                # Write table rows
                print(f"🔍 DEBUG: Writing table row {idx} with {len(dependency_rows)} dependency rows")
                if dependency_rows:
                    ef.write(f"<tr><td rowspan='{len(dependency_rows)}'>{idx}</td><td rowspan='{len(dependency_rows)}'>{custodian}</td><td rowspan='{len(dependency_rows)}'>{base_display}</td><td>{dependency_rows[0]}</td><td rowspan='{len(dependency_rows)}'>{vuln_details}</td></tr>\n")
                    for dep_row in dependency_rows[1:]:
                        ef.write(f"<tr><td>{dep_row}</td></tr>\n")
                else:
                    ef.write(f"<tr><td>{idx}</td><td>{custodian}</td><td>{base_display}</td><td>-</td><td>{vuln_details}</td></tr>\n")
            
            ef.write("</table>\n")
        print(f"✅ Personal email HTML saved to {email_html_path}")
        
    else:
        print("ℹ️ No packages matched Personal Report criteria. Skipping personal report generation.")

    # Summary logging
    total = len(rows)
    base_count = sum(1 for r in rows if r['Package Type'] == 'Base Package')
    dep_count = total - base_count

    def count_vulnerabilities(rows, package_type, used_only=True):
        """Count vulnerable packages by type and usage status."""
        return sum(
            1 for r in rows
            if r['Package Type'] == package_type
            and r['Current Version Vulnerable?'] == 'Yes'
            and (
                ('not used' not in r['Remarks'].lower()) if used_only
                else ('not used' in r['Remarks'].lower())
            )
        )

    base_vuln_used = count_vulnerabilities(rows, 'Base Package', used_only=True)
    base_vuln_notused = count_vulnerabilities(rows, 'Base Package', used_only=False)
    dep_vuln_used = count_vulnerabilities(rows, 'Dependency Package', used_only=True)
    dep_vuln_notused = count_vulnerabilities(rows, 'Dependency Package', used_only=False)

    logger.info("📦 Weekly Report Summary")
    logger.info(f"🔍 Total packages scanned: {total} (Base: {base_count}, Dependency: {dep_count})")
    logger.info("🚨 Vulnerabilities found in current versions:")
    logger.info(
        f"   • Base packages: {base_vuln_used} / {base_count}"
        f" ({base_vuln_notused} packages are not used)"
    )
    logger.info(
        f"   • Dependency packages: {dep_vuln_used} / {dep_count}"
        f" ({dep_vuln_notused} packages are not used)"
    )

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Execution interrupted by user.")
        sys.exit(1)
