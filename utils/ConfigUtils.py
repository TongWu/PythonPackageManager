import utils
import os
import csv
import re
import logging
from logging import StreamHandler, Formatter
from datetime import datetime, timedelta
from dotenv import load_dotenv
from utils.SGTUtils import now_sg, SGTFormatter

load_dotenv(dotenv_path=".env")

FULL_RELOAD_PACKAGES = os.getenv("FULL_RELOAD_PACKAGES", "False").lower() == "true"
BASE_PACKAGE_TXT = os.getenv("BASE_PACKAGE_TXT", "base_package_list.txt")
BASE_PACKAGE_CSV = os.getenv("BASE_PACKAGE_CSV", "BasePackageWithDependencies.csv")
CHECK_DEPENDENCY_SCRIPT = os.getenv("CHECK_DEPENDENCY_SCRIPT", "CheckDependency.py")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger

def get_report_paths() -> dict:
    """
    Generate all report file paths using current week and timestamp.

    Returns:
        dict: Dictionary with keys 'dir', 'csv', 'html', 'json', 'failed' pointing to file paths.
    """
    today = datetime.today()
    monday = today - timedelta(days=today.weekday()) 
    folder_name = monday.strftime("%Y-%m-%d")
    timestamp_sg = now_sg().strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join("WeeklyReport", folder_name)
    os.makedirs(output_dir, exist_ok=True)

    return {
        "dir": output_dir,
        "csv": os.path.join(output_dir, f"WeeklyReport_{timestamp_sg}.csv"),
        "html": os.path.join(output_dir, f"WeeklyReport_{timestamp_sg}.html"),
        "json": os.path.join(output_dir, f"WeeklyReport_{timestamp_sg}.json"),
        "failed": os.path.join(output_dir, f"FailedVersions_{timestamp_sg}.txt")
    }

def get_report_output_folder(base: str = "WeeklyReport") -> str:
    """
    Create and return the output folder path for the current week's report.

    This function computes the folder name based on the Monday of the current week,
    creates the directory if it does not exist, and returns the path.

    Args:
        base (str): Base directory name for report folders. Default is "WeeklyReport".

    Returns:
        str: Full path to the output directory for the current week.
    """
    today = datetime.today()
    monday = today - timedelta(days=today.weekday()) 
    folder_name = monday.strftime("%Y-%m-%d")
    path = os.path.join(base, folder_name)
    os.makedirs(path, exist_ok=True)
    return path

def get_monthly_report_output_folder(base: str = "MonthlyReport") -> str:
    """
    Create and return the output folder path for the current month's report.

    This function computes the folder name based on the Monday of the current month,
    creates the directory if it does not exist, and returns the path.

    Args:
        base (str): Base directory name for report folders. Default is "MonthlyReport".

    Returns:
        str: Full path to the output directory for the current month.
    """
    today = datetime.today()
    folder_name = today.strftime("%Y-%m")
    path = os.path.join(base, folder_name)
    os.makedirs(path, exist_ok=True)
    return path

def load_base_packages() -> set:
    """
    Load base packages from either a CSV or a TXT file based on global setting.

    Returns:
        set: Set of lowercase package names classified as base packages.
    """
    base_set = set()
    try:
        if FULL_RELOAD_PACKAGES:
            logger.warning(f"FULL RELOAD PYTHON PACKAGES, CALLING {CHECK_DEPENDENCY_SCRIPT}")
            # Regenerate Base Packages Dependencies before loading
            run_py(CHECK_DEPENDENCY_SCRIPT)

            with open(BASE_PACKAGE_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    base_pkg = row.get("Base Package", "").strip()
                    if base_pkg:
                        base_set.add(base_pkg.lower())
            logger.info(f"Loaded {len(base_set)} base packages from {BASE_PACKAGE_CSV}")
            logger.debug(f"Base package list: \n {base_set}")
        else:
            with open(BASE_PACKAGE_TXT, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        base_set.add(line.lower())
            logger.info(f"Loaded {len(base_set)} base packages from {BASE_PACKAGE_TXT}")
            logger.debug(f"Base package list: \n {base_set}")
    except Exception as e:
        logger.warning(f"Failed to load base package list: {e}")
    return base_set

def parse_requirements(requirements_file: str) -> dict:
    """
    Parse a requirements.txt file into a dictionary.

    Supports basic parsing of version constraints like ==, >=, <=, ~=, !=.

    Args:
        requirements_file (str): Path to a pip requirements file.

    Returns:
        dict: Mapping of package names to their specified version strings.
    """
    pkgs = {}
    with open(requirements_file, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            name = re.split(r"[<>=!~]+", line)[0].strip()
            m = re.search(r"(==|>=|<=|~=|!=)(.+)", line)
            ver = m.group(2).strip() if m else 'unknown'
            pkgs[name] = ver
    logger.info(f"Parsed {len(pkgs)} packages from {requirements_file}")
    return pkgs

def extract_dependencies(info: dict) -> list:
    """
    Extract dependency information from PyPI metadata.

    Args:
        info (dict): JSON metadata returned from PyPI.

    Returns:
        list: List of dependency strings (usually from 'requires_dist').
    """
    return info.get('info', {}).get('requires_dist') or []
