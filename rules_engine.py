"""
rules_engine.py — Effective policy computation for Deep42.

Contract (from spec §3.3):
  1. Find all rules where path_prefix is a prefix of target_path (boundary-aware).
  2. Choose the MOST SPECIFIC rule (deepest prefix = longest match).
  3. Tie-breaker: exclude wins.
  4. If no rules match: return default_policy.

Boundary-aware means:
  /Work      matches /Work and /Work/...  but NOT /Workshop
  Enforced by checking that the next char after the prefix is '/' or end-of-string.
"""

from typing import List, Dict, Literal

PolicyType = Literal["include", "exclude"]


def _is_prefix_match(prefix: str, target: str) -> bool:
    """True if prefix is a path-boundary-aware prefix of target."""
    prefix = prefix.rstrip("/")
    if prefix == "":
        return True  # empty prefix matches everything
    if target == prefix:
        return True
    if target.startswith(prefix + "/"):
        return True
    return False


def effective_policy(
    target_path: str,
    default_policy: PolicyType,
    rules: List[Dict],
) -> PolicyType:
    """
    Compute the effective include/exclude policy for target_path.

    rules: list of dicts with 'path_prefix' and 'policy' keys.
    """
    matching = [r for r in rules if _is_prefix_match(r["path_prefix"], target_path)]

    if not matching:
        return default_policy

    # Group by depth (length of prefix)
    max_depth = max(len(r["path_prefix"]) for r in matching)
    deepest = [r for r in matching if len(r["path_prefix"]) == max_depth]

    # Tie-breaker: exclude wins
    policies = {r["policy"] for r in deepest}
    if "exclude" in policies:
        return "exclude"
    return "include"


def apply_policy_to_items(
    items: List[Dict],
    default_policy: PolicyType,
    rules: List[Dict],
) -> List[Dict]:
    """
    Annotate a list of browse items with their effective_policy.
    Each item must have a 'path' key.
    """
    for item in items:
        item["effective_policy"] = effective_policy(
            item["path"], default_policy, rules
        )
    return items
