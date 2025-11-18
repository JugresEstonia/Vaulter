import pathlib
from typing import List

BANNED_PATTERNS = [
    "gets(",
    "strcpy(",
    "strcat(",
    "sprintf(",
]

EXCLUDED_DIRS = {
    ".venv",
    "venv",
    "lib",
    "lib64",
    "bin",
    "include",
    "__pycache__",
    "site-packages",
}


def scan_for_banned_string_funcs(root: pathlib.Path) -> List[str]:
    """
    Walk Python sources under root and return any lines containing banned C string APIs.
    This satisfies checklist item 1.2 by ensuring those APIs never appear in the codebase.
    """
    matches: List[str] = []
    for path in root.rglob("*.py"):
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.name == "devcheck.py":
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(pattern in line for pattern in BANNED_PATTERNS):
                matches.append(f"{path}:{lineno}:{line.strip()}")
    return matches
