import re
import pkg_resources
import subprocess
import json
import pandas as pd

requirements_file = "/workspaces/mend_scan_template/requirements_full_list.txt"
# Step 1: Load base package list and save original line
base_packages = {}  # {pkg_key: original_line}
with open(requirements_file) as f:
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

# Step 2: Install all packages one by one (ignore dependency conflicts, skip failures)
for pkg_key, pkg_line in base_packages.items():
    print(f"⬇️ Installing: {pkg_line}")
    result = subprocess.run([
        "pip", "install", "--no-deps", "--ignore-installed", pkg_line
    ], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"⚠️ Failed to install {pkg_line}. Skipping.\nError: {result.stderr}")
    else:
        print(f"✅ Installed: {pkg_line}")

# Step 3: Ensure pipdeptree is installed
subprocess.run(["pip", "install", "--quiet", "pipdeptree"], check=True)

# Step 4: Get the full dependency tree as JSON
result = subprocess.run(["pipdeptree", "--json"], capture_output=True, text=True)
data = json.loads(result.stdout)

# Step 5: Build a map: {parent_pkg: [dep_name, dep_name, ...]}
tree_map = {}
pkg_versions = {}
all_dependencies_set = set()  # 👈 新增：记录所有被依赖的包

for item in data:
    parent = item["package"]["key"]
    parent_version = item["package"]["installed_version"]
    pkg_versions[parent] = parent_version
    deps = []
    for dep in item.get("dependencies", []):
        dep_name = dep["key"]
        deps.append(dep_name)
        all_dependencies_set.add(dep_name)  # 👈 记录到依赖包集合
    tree_map[parent] = deps

# Recursive dependency collector
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

# Step 6: Collect full dependencies for each base package (only top-level packages)
rows = []
for base in base_packages:
    if base in all_dependencies_set:
        print(f"ℹ️ Skipping {base} because it's a dependency of another package.")
        continue

    version = pkg_versions.get(base, "")
    full_deps = get_all_dependencies(base, tree_map)
    unique_deps = sorted(set(full_deps))
    row = {
        "Base Package": base,
        "Base Version": version,
    }
    for idx, dep in enumerate(unique_deps, start=1):
        row[f"dependsBy{idx}"] = dep
    rows.append(row)

# Step 7: Save to CSV
df = pd.DataFrame(rows)
df.to_csv("TRM_base_packages_with_dependencies.csv", index=False)
print("✅ Exported to TRM_base_packages_with_dependencies.csv")
print(df)
