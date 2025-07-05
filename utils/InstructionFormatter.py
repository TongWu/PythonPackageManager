#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utilities to convert upgrade instruction JSON to human-readable text."""

from typing import Any, Mapping, Optional


def instruction_to_text(instruction: Optional[Mapping[str, Any]]) -> str:
    """
    Convert an upgrade instruction dictionary into a concise human-readable string.
    
    Returns an empty string if the instruction is missing or lacks a base package. If dependencies are present, lists them after the base package upgrade message; otherwise, only the base package upgrade is mentioned.
    
    Returns:
        str: Human-readable upgrade instruction, or an empty string if input is invalid.
    """
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


import json

def instruction_to_detailed_text(instruction: Optional[Mapping[str, Any]], current_deps_json: str = "{}") -> str:
    """
    Generate a detailed human-readable description of an upgrade instruction, including reasons for dependency updates.
    
    If dependencies are present, compares each target dependency version with the current version (parsed from a JSON string). Marks dependencies as either upgrades from a known version or as new requirements. Returns a string summarizing the base package upgrade and detailed dependency updates. Returns an empty string if the instruction is missing or incomplete.
    
    Parameters:
        instruction (Optional[Mapping[str, Any]]): The upgrade instruction containing at least a "base_package" key and optionally a "dependencies" list.
        current_deps_json (str): A JSON string representing the current dependencies, expected to contain a "dependencies" list in the format ["package==version", ...].
    
    Returns:
        str: A detailed upgrade summary, or an empty string if input is invalid.
    """
    if not instruction:
        return ""
    
    base_pkg = instruction.get("base_package", "")
    if not base_pkg:
        return ""
    
    deps = instruction.get("dependencies", []) or []
    
    # Parse current dependencies for comparison
    try:
        current_deps_data = json.loads(current_deps_json)
        current_deps = {dep.split('==')[0]: dep.split('==')[1] if '==' in dep else 'unknown' 
                      for dep in current_deps_data.get('dependencies', []) if current_deps_data}
    except (json.JSONDecodeError, KeyError, AttributeError):
        current_deps = {}
    
    if deps:
        dep_details = []
        for dep in deps:
            dep_name = dep.split('==')[0] if '==' in dep else dep
            dep_version = dep.split('==')[1] if '==' in dep else 'unknown'
            current_version = current_deps.get(dep_name, 'unknown')
            
            if current_version not in ('unknown', dep_version):
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
