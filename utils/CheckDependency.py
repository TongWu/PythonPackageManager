import re
import pkg_resources
import subprocess
import json
import pandas as pd
import logging
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# ---------------- Logging Configuration ----------------
from logging import Formatter, StreamHandler
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from pytz import timezone as ZoneInfo  # fallback for Python <3.9

SG_TZ = ZoneInfo("Asia/Singapore")

class SGTFormatter(Formatter):
    """
    Custom logging formatter that outputs timestamps in Asia/Singapore timezone.
    """
    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created, SG_TZ)
        if datefmt:
            return ct.strftime(datefmt)
        return ct.isoformat()

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger

# ---------------- Logging Configuration with SGT timezone ----------------
load_dotenv(dotenv_path=".env")

REQUIREMENTS_FILE = os.getenv("REQUIREMENTS_FILE", "src/requirements_full_list.txt")
BASE_PACKAGE_CSV = os.getenv("BASE_PACKAGE_CSV", "src/BasePackageWithDependencies.csv")
logger.info(f"Reading base packages from {REQUIREMENTS_FILE}")

# Step 1: Load base package list and save original line
base_packages = {}
with open(REQUIREMENTS_FILE) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg_name = re.split(r"[<>=!~]+", line)[0]
        try:
            pkg_key = pkg_resources.Requirement.parse(pkg_name).key
        except Exception:
            pkg_key = pkg_name.lower()
        base_packages[pkg_key] = line

logger.info(f"Found {len(base_packages)} base packages.")

# Step 2: Install all packages one by one (ignore dependency conflicts, skip failures)
total_pkgs = len(base_packages)
for idx, (pkg_key, pkg_line) in enumerate(base_packages.items(), 1):
    logger.info(f"[{idx}/{total_pkgs}] ⬇️ Installing: {pkg_line}")
    result = subprocess.run(
        ["pip", "install", "--no-deps", "--ignore-installed", pkg_line],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.warning(f"[{idx}/{total_pkgs}] ⚠️ Failed to install {pkg_line}. Skipping.\n{result.stderr.strip()}")
    else:
        logger.info(f"[{idx}/{total_pkgs}] ✅ Installed: {pkg_line}")

# Step 3: Ensure pipdeptree is installed
# logger.info("Installing pipdeptree...")
# subprocess.run(["pip", "install", "--quiet", "pipdeptree"], check=True)

# Step 4: Get full dependency tree
logger.info("Extracting dependency tree via pipdeptree...")
result = subprocess.run(["pipdeptree", "--json", "--all"], capture_output=True, text=True)
data = json.loads(result.stdout)

# Step 5: Parse tree into map
logger.info("Parsing dependency tree...")
tree_map = {}
pkg_versions = {}
all_dependencies_set = set()

for item in data:
    parent = item["package"]["key"]
    parent_version = item["package"]["installed_version"]
    pkg_versions[parent] = parent_version
    deps = []
    for dep in item.get("dependencies", []):
        dep_name = dep["key"]
        deps.append(dep_name)
        all_dependencies_set.add(dep_name)
    tree_map[parent] = deps

# Step 6: Identify pure base packages
logger.info("Filtering pure base packages...")
all_depended_packages = set()
for deps in tree_map.values():
    all_depended_packages.update(deps)

pure_base_packages = [pkg for pkg in base_packages if pkg not in all_depended_packages]
logger.info(f"Found {len(pure_base_packages)} pure base packages.")

# Recursive function to get full dependency chain
def get_all_dependencies(pkg_key, tree_map, visited=None):
    if visited is None:
        visited = set()
    if pkg_key in visited:
        return []
    visited.add(pkg_key)

    deps = []
    for dep in tree_map.get(pkg_key, []):
        deps.append(dep)
        deps.extend(get_all_dependencies(dep, tree_map, visited))
    return deps

# Step 7: Collect dependencies for each base package
logger.info("Building full dependency map...")
rows = []
for base in pure_base_packages:
    full_deps = get_all_dependencies(base, tree_map)
    unique_deps = sorted(set(full_deps))
    row = {
        "Base Package": base,
    }
    for idx, dep in enumerate(unique_deps, start=1):
        row[f"dependsBy{idx}"] = dep
    rows.append(row)

# Step 8: Export to CSV and base package list
df = pd.DataFrame(rows)
df.to_csv(BASE_PACKAGE_CSV, index=False)
logger.info(f"✅ Exported dependency map to {BASE_PACKAGE_CSV}")

# Also export pure base package list
base_package_list_file = os.path.join("src", "base_package_list.txt")
with open(base_package_list_file, "w") as f:
    for pkg in sorted(pure_base_packages):
        f.write(pkg + "\n")
logger.info(f"✅ Exported base package list to {base_package_list_file}")
