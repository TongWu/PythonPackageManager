#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utilities to convert upgrade instruction JSON to human-readable text."""

from typing import Any, Mapping, Optional


def instruction_to_text(instruction: Optional[Mapping[str, Any]]) -> str:
    """Return a human-readable string from an upgrade instruction dict."""
    if not instruction:
        return ""
    base_pkg = instruction.get("base_package", "")
    if not base_pkg:
        return ""
    deps = instruction.get("dependencies", []) or []
    if deps:
        dep_str = ", ".join(deps)
        return f"Upgrade {base_pkg} and update dependencies: {dep_str}"
    return f"Upgrade {base_pkg}"


def instruction_to_detailed_text(instruction: Optional[Mapping[str, Any]], current_deps_json: str = "{}") -> str:
    """Return a detailed human-readable string with dependency upgrade reasons."""
    if not instruction:
        return ""
    
    base_pkg = instruction.get("base_package", "")
    if not base_pkg:
        return ""
    
    deps = instruction.get("dependencies", []) or []
    
    # Parse current dependencies for comparison
    import json
    try:
        current_deps_data = json.loads(current_deps_json)
        current_deps = {dep.split('==')[0]: dep.split('==')[1] if '==' in dep else 'unknown' 
                      for dep in current_deps_data.get('dependencies', []) if current_deps_data}
    except:
        current_deps = {}
    
    if deps:
        dep_details = []
        for dep in deps:
            dep_name = dep.split('==')[0] if '==' in dep else dep
            dep_version = dep.split('==')[1] if '==' in dep else 'unknown'
            current_version = current_deps.get(dep_name, 'unknown')
            
            if current_version != 'unknown' and current_version != dep_version:
                dep_details.append(f"{dep} (upgrade from {current_version})")
            else:
                dep_details.append(f"{dep} (new requirement)")
        
        dep_str = "; ".join(dep_details)
        return f"Upgrade {base_pkg} and update dependencies: {dep_str}"
    
    return f"Upgrade {base_pkg}"


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: InstructionFormatter.py '<json-string>'")
        sys.exit(1)

    try:
        data = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        sys.exit(1)

    print(instruction_to_text(data))
