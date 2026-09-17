"""Argument-level scoping on top of tool-name scoping.

A `Capability` already limits *which tools* a grant may call
(`capability.py`'s `tools` field). `ArgumentRule` narrows that further to
*which arguments* those tools may be called with -- e.g. "send_reply is
allowed, but only to these addresses." Rules travel inside the signed
`Capability.argument_constraints`, so widening them after signing breaks the
Ed25519 signature exactly like widening `tools` does (see capability.py).

`TaskPolicy` is the human-editable, *unsigned* declarative input a task is
described with (a JSON or YAML file) -- it is never trusted directly by the
broker. It only becomes enforceable once a human approves it via consent and
`Issuer.mint()` turns it into a signed `Capability`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Operator = Literal["equals", "in", "not_in", "regex"]

_MISSING = object()


@dataclass(frozen=True)
class ArgumentRule:
    field: str  # dotted path into the call arguments, e.g. "to" or "filters.folder"
    operator: Operator
    value: Any  # str for equals/regex, list[str] for in/not_in

    def to_dict(self) -> dict:
        return {"field": self.field, "operator": self.operator, "value": self.value}

    @classmethod
    def from_dict(cls, d: dict) -> "ArgumentRule":
        return cls(field=d["field"], operator=d["operator"], value=d["value"])


def _resolve_field(arguments: dict, dotted_field: str) -> Any:
    current: Any = arguments
    for part in dotted_field.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _rule_fails(rule: ArgumentRule, actual: Any) -> bool:
    if actual is _MISSING:
        return True
    if rule.operator == "equals":
        return actual != rule.value
    if rule.operator == "in":
        return actual not in rule.value
    if rule.operator == "not_in":
        return actual in rule.value
    if rule.operator == "regex":
        return not isinstance(actual, str) or re.fullmatch(rule.value, actual) is None
    raise ValueError(f"Unknown argument rule operator: {rule.operator!r}")


def match_arguments(
    tool_name: str,
    call_arguments: dict,
    constraints: dict[str, list[ArgumentRule]],
) -> tuple[bool, str | None]:
    """Checks `call_arguments` against every rule registered for `tool_name`.

    A tool absent from `constraints` (or mapped to an empty rule list) is
    unconstrained beyond the existing tool-name scope check, so plain
    tool-name-only grants keep working exactly as they do today.

    Returns (True, None) on pass, or (False, reason) naming the first field
    that failed and why -- callers (the broker) use `reason` verbatim as the
    denial reason.
    """
    for rule in constraints.get(tool_name, []):
        actual = _resolve_field(call_arguments, rule.field)
        if _rule_fails(rule, actual):
            shown = "<missing>" if actual is _MISSING else actual
            reason = (
                f"Capability does not permit these arguments: {rule.field} "
                f"(expected {rule.operator} {rule.value!r}, got {shown!r})."
            )
            return False, reason
    return True, None


@dataclass(frozen=True)
class ToolGrant:
    tool: str
    arguments: tuple[ArgumentRule, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TaskPolicy:
    """The unsigned, human-editable request a `Capability` is minted from."""

    subject: str
    audience: str
    ttl_seconds: int
    quota: int
    grants: tuple[ToolGrant, ...]

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(g.tool for g in self.grants)

    @property
    def argument_constraints(self) -> dict[str, list[ArgumentRule]]:
        return {g.tool: list(g.arguments) for g in self.grants if g.arguments}


def _parse_policy_dict(data: dict) -> TaskPolicy:
    required = {"subject", "audience", "ttl_seconds", "quota", "grants"}
    missing = required - data.keys()
    if missing:
        raise ValueError(f"Task policy missing required field(s): {sorted(missing)}")

    grants = []
    for raw_grant in data["grants"]:
        if "tool" not in raw_grant:
            raise ValueError(f"Task policy grant missing 'tool': {raw_grant!r}")
        rules = tuple(ArgumentRule.from_dict(r) for r in raw_grant.get("arguments", []))
        grants.append(ToolGrant(tool=raw_grant["tool"], arguments=rules))

    return TaskPolicy(
        subject=data["subject"],
        audience=data["audience"],
        ttl_seconds=int(data["ttl_seconds"]),
        quota=int(data["quota"]),
        grants=tuple(grants),
    )


def load_task_policy(path: str | Path) -> TaskPolicy:
    """Loads a `TaskPolicy` from a `.json` file, or a `.yaml`/`.yml` file if
    PyYAML is installed (not a hard dependency of this project).
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "Reading a .yaml task policy requires PyYAML (`pip install pyyaml`); "
                "use a .json policy file instead if you'd rather not add the dependency."
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    return _parse_policy_dict(data)


def validate_against_tools_list(policy: TaskPolicy, available_tool_names: set[str]) -> None:
    """Fails closed if `policy` references a tool that doesn't exist on the
    live downstream server, instead of silently denying every call to it at
    authorize-time.
    """
    unknown = set(policy.tools) - available_tool_names
    if unknown:
        raise ValueError(
            f"Task policy references tool(s) not offered by the target server: {sorted(unknown)}"
        )
