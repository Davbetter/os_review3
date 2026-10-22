"""Multi-tiered input guardrails: regex sanitisers + workspace path confinement."""
import re
from pathlib import Path


class SecurityViolation(ValueError):
    """Raised when input or a path violates a guardrail."""


# (category, regex). Checked against raw user input AND every string tool argument.
BLOCKED_PATTERNS = [
    # Destructive Command Blocker
    ("Destructive Command Blocker", r"\brm\s+-rf\b"),
    ("Destructive Command Blocker", r"\brm\s+-fr\b"),
    ("Destructive Command Blocker", r"\bdd\s+(if|of)="),
    ("Destructive Command Blocker", r"\bmkfs(\.\w+)?\b"),
    ("Destructive Command Blocker", r"\bshred\b"),
    ("Destructive Command Blocker", r":\(\)\s*\{"),  # fork bomb
    ("Destructive Command Blocker",
     r"\b(delete|erase|wipe|format|destroy|nuke)\b.{0,30}\b(everything|all (my )?files|(my |the )?(drive|disk|filesystem|system))\b"),
    # Privilege Escalation Blocker
    ("Privilege Escalation Blocker", r"\bsudo\b"),
    ("Privilege Escalation Blocker", r"(^|[;&|]\s*)su(\s|$)"),
    ("Privilege Escalation Blocker", r"\bchmod\s+(-\w+\s+)?[0-7]?777\b"),
    ("Privilege Escalation Blocker", r"\bchown\s+-R\b"),
    # Path Traversal Blocker
    ("Path Traversal Blocker", r"\.\./"),
    ("Path Traversal Blocker", r"\.\.\\"),
]
_COMPILED = [(cat, pat, re.compile(pat, re.IGNORECASE)) for cat, pat in BLOCKED_PATTERNS]


def sanitize_and_validate(text: str) -> None:
    """Raise SecurityViolation if `text` matches any blocked pattern."""
    for category, pattern, rx in _COMPILED:
        if rx.search(text):
            raise SecurityViolation(
                f"Security Rule Violation: Intercepted blocked pattern '{pattern}' ({category})"
            )


def resolve_in_workspace(path: str, workspace: Path) -> Path:
    """Resolve `path` (relative to workspace) and ensure it stays inside it.

    Uses resolve() so symlinks and `..` cannot escape the authorised workspace.
    """
    if "\x00" in path:
        raise SecurityViolation("Security Rule Violation: null byte in path")
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = workspace / p
    p = p.resolve()
    if p != workspace and not p.is_relative_to(workspace):
        raise SecurityViolation(
            f"Security Rule Violation: path '{path}' is outside the permitted workspace ({workspace})"
        )
    return p
