# Python Packages Manager

A comprehensive, self-hosted solution for automated Python dependency management, vulnerability scanning, upgrade recommendations, and compliance reporting. Designed for teams and organizations seeking regular, auditable, and actionable insights into their Python project dependencies.

The repo is now available in DeepWiki.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/TongWu/PythonPackageManager)

---

## Table of Contents

1. [Overview](#overview)
2. [Repository Structure](#repository-structure)
3. [Installation & Local Usage](#installation--local-usage)
4. [Configuration: Environment Variables](#configuration-environment-variables)
5. [Maintaining Data Files](#maintaining-data-files)
6. [Generating Reports Locally](#generating-reports-locally)
7. [Understanding Script Dependencies](#understanding-script-dependencies)
8. [Viewing and Interpreting Reports](#viewing-and-interpreting-reports)
9. [GitHub Actions Automation](#github-actions-automation)
10. [Customizing & Troubleshooting](#customizing--troubleshooting)
11. [License](#license)

---

## Overview

**Python Packages Manager** automates the end-to-end process of Python dependency analysis, security scanning, and upgrade planning. It:

- **Builds a full dependency tree** from your requirements.
- **Scans for known vulnerabilities** using [pip-audit](https://github.com/pypa/pip-audit) and [OSV](https://osv.dev/).
- **Suggests safe upgrades** (minor/patch) for outdated or vulnerable packages.
- **Assigns custodians** (owners/teams) to each package for accountability.
- **Generates detailed reports** in CSV, HTML, JSON, and Excel formats, including personal and monthly summaries.
- **Integrates with GitHub Actions** for scheduled or on-demand automation and cloud sync.

This tool is ideal for organizations that require regular, auditable, and actionable insights into their Python dependencies for compliance, security, and maintenance.

---

## Repository Structure

```
/ (root)
├── .github/
│   └── workflows/            # GitHub Actions workflows (CI/CD)
├── src/                      # Input & mapping data files
│   ├── requirements_full_list.txt
│   ├── base_package_list.txt
│   ├── BasePackageWithDependencies.csv  # generated, do not edit manually
│   ├── custodian.csv         # package-to-team mapping
│   └── NotUsed.txt           # packages to exclude
├── templates/                # Jinja2 HTML templates
│   └── weekly_report.html.j2
├── utils/                    # Helper modules
│   ├── CheckDependency.py    # builds dependency CSV
│   ├── ConfigUtils.py        # path & parse utilities
│   ├── CustodianUtils.py     # custodian mapping & sort key
│   ├── PyPiUtils.py          # PyPI metadata fetching
│   ├── VersionSuggester.py   # safe upgrade logic
│   ├── VulnChecker.py        # pip-audit & OSV checks
│   ├── UpgradeInstruction.py # format upgrade steps
│   └── SGTUtils.py           # custom logger & time helper
├── WeeklyReport/             # Output reports by date
│   └── YYYY-MM-DD/
│       ├── WeeklyReport_*.csv
│       ├── WeeklyReport_*.html
│       ├── WeeklyReport_*.json
│       └── FailedVersions_*.txt
├── MonthlyReport/            # Monthly Excel reports
├── temp/                     # Personal report outputs
├── GenerateReport.py         # Main report generator (executable)
├── requirements.txt          # Python dependencies
└── .env                      # Environment configuration
```

---

## Installation & Local Usage

1. **Clone the repository and set up a virtual environment:**

   ```bash
   git clone https://github.com/your-org/PythonPackagesManager.git
   cd PythonPackagesManager
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Prepare the environment configuration:**
   - Copy `.env.example` to `.env` (or create `.env` manually).
   - Edit the values as needed (see [Configuration](#configuration-environment-variables)).

---

## Configuration: Environment Variables

All runtime settings are managed via the `.env` file in the project root. Key variables include:

- `FULL_RELOAD_PACKAGES`: If `True`, always re-scan dependencies.
- `BASE_PACKAGE_TXT`, `BASE_PACKAGE_CSV`, `REQUIREMENTS_FILE`, `CUSTODIAN_LIST`, `NOTUSED_PACKAGES`: Paths to main data files.
- `PIP_AUDIT_CMD`: Command for vulnerability scanning (default: `pip-audit --format json`).
- `SEMAPHORE_NUMBER`: Max parallel vulnerability checks.
- `CUSTODIAN_1`, `CUSTODIAN_2`: Base64-encoded custodian/team names (decoded at runtime).
- `PYPI_URL_TEMPLATE`: PyPI API endpoint.
- `PERSONAL_REPORT_DIR`: Output directory for personal reports.

**To update:**
- Edit `.env` directly in your editor.
- For new custodians, add new `CUSTODIAN_N` variables and update `custodian.csv` accordingly.

---

## Maintaining Data Files

The following files must be maintained for accurate and meaningful reports:

| File                                   | Purpose & Maintenance                                      |
|----------------------------------------|------------------------------------------------------------|
| `src/requirements_full_list.txt`       | Main list of all required packages (edit as needed)        |
| `src/base_package_list.txt`            | List of base packages (edit as needed)                     |
| `src/custodian.csv`                    | Mapping: package → custodian/team (edit as needed)         |
| `src/NotUsed.txt`                      | Packages to exclude from reporting (edit as needed)        |
| `src/BasePackageWithDependencies.csv`  | Generated by script; **do not edit manually**              |

- **Add/remove packages:** Update `requirements_full_list.txt` and, if needed, `base_package_list.txt` and `custodian.csv`.
- **Change custodians:** Update `custodian.csv` and, if new, add base64-encoded name to `.env`.
- **Exclude packages:** Add to `NotUsed.txt` (one per line, lowercase).

---

## Generating Reports Locally

There are two main executable scripts:

1. **Dependency Tree Generation**
   - Run: `python utils/CheckDependency.py`
   - Reads `src/requirements_full_list.txt` and outputs `src/BasePackageWithDependencies.csv` (do not edit this output manually).

2. **Weekly Report Generation**
   - Run: `python GenerateReport.py --output all`
   - Options: `--output csv html json all` (default: all)
   - Reads all maintained files, fetches PyPI metadata, checks vulnerabilities, suggests upgrades, and generates:
     - CSV, HTML, JSON reports in `WeeklyReport/YYYY-MM-DD/`
     - Monthly Excel report in `MonthlyReport/`
     - Personal report in `temp/` (for email/notification use)

**Typical workflow:**
1. Update/maintain all required data files.
2. Run `CheckDependency.py` to refresh dependency tree.
3. Run `GenerateReport.py` to produce all reports.

---

## Understanding Script Dependencies

- `CheckDependency.py` **must be run first** to generate the latest dependency tree (`BasePackageWithDependencies.csv`).
- `GenerateReport.py` depends on all maintained files and the generated dependency CSV.
- Utility modules in `utils/` are imported by the main scripts for parsing, metadata fetching, vulnerability checking, upgrade suggestion, and report formatting.

---

## Viewing and Interpreting Reports

- **HTML Report:**
  - Open the latest file in `WeeklyReport/YYYY-MM-DD/WeeklyReport_*.html` with your browser.
- **CSV/JSON Report:**
  - Open with Excel or your preferred editor for further analysis.
- **Monthly Excel Report:**
  - Found in `MonthlyReport/`, includes summary, custodian, and detailed sheets.
- **Personal Report:**
  - For notification or email, found in `temp/`.
- **Failed Versions:**
  - If any package version fails vulnerability check, see `FailedVersions_*.txt` in the weekly report folder.

---

## GitHub Actions Automation

This project supports full automation via GitHub Actions:

- **Workflow files:** Located in `.github/workflows/` (e.g., `GenerateReport.yml`).
- **Triggers:**
  - Scheduled (e.g., every Monday & Thursday at UTC midnight)
  - Manual (via workflow dispatch)
- **Steps:**
  1. Checkout code
  2. Setup Python & dependencies
  3. (Optional) Setup rclone for cloud sync
  4. Run `CheckDependency.py` and `GenerateReport.py`
  5. Commit & push generated reports
  6. (Optional) Sync reports to cloud storage

### Required GitHub Secrets

- `PYPI_TOKEN` (if private packages or publishing is needed)
- `RCLONE_CONF_BASE64` (if using rclone for cloud sync)
- Any other secrets referenced in your workflow YAML

**To set secrets:** Go to GitHub → Settings → Secrets and variables → Actions → New repository secret.

### Using the Action

- The workflow will run automatically on schedule or can be triggered manually.
- Reports will be committed to the repository and/or synced to cloud storage as configured.
- Check workflow logs for troubleshooting.

---

## Customizing & Troubleshooting

- **To change environment variables:** Edit `.env` and commit changes.
- **To add new custodians:** Add a new base64-encoded variable in `.env` and update `custodian.csv`.
- **To add new packages:** Update `requirements_full_list.txt` and rerun the scripts.
- **To exclude packages:** Add to `NotUsed.txt`.
- **To customize HTML report:** Edit `templates/weekly_report.html.j2` (supports Jinja2 syntax).
- **For errors:** Check logs in the console or GitHub Actions logs. Review `FailedVersions_*.txt` for problematic packages.

---

## License

Released under the [MIT License](LICENSE).
