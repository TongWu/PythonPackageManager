#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utilities to convert upgrade instruction JSON to human-readable text."""

from typing import Any, Mapping


def instruction_to_text(instruction: Mapping[str, Any] | None) -> str:
    """Return a human-readable string from an upgrade instruction dict."""
    if not instruction:
        return ""
    base_pkg = instruction.get("base_package", "")
    deps = instruction.get("dependencies", []) or []
    if deps:
        dep_str = ", ".join(deps)
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
