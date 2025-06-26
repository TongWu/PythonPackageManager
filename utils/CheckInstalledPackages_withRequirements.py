import re
import subprocess
import pkg_resources

requirements_file = "/workspaces/mend_scan_template/requirements_full_list.txt"

required_packages = set()
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
        required_packages.add(pkg_key)

print(f"📦 Found {len(required_packages)} packages in {requirements_file}.")

installed_packages = {pkg.key for pkg in pkg_resources.working_set}

print(f"✅ {len(installed_packages)} packages are currently installed.")

missing_packages = required_packages - installed_packages

if missing_packages:
    print(f"❗ {len(missing_packages)} packages are listed in {requirements_file} but NOT installed:")
    for pkg in sorted(missing_packages):
        print(f"- {pkg}")
else:
    print("🎉 All packages in requirements.txt are installed!")
