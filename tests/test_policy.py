import json

import pytest

from covenant.policy import ArgumentRule, load_task_policy, match_arguments, validate_against_tools_list


# --- match_arguments: one property per operator -----------------------------


def test_equals_rule_allows_exact_value():
    rules = {"send_reply": [ArgumentRule(field="body", operator="equals", value="ok")]}
    ok, reason = match_arguments("send_reply", {"body": "ok"}, rules)
    assert ok is True
    assert reason is None


def test_equals_rule_denies_other_value():
    rules = {"send_reply": [ArgumentRule(field="body", operator="equals", value="ok")]}
    ok, reason = match_arguments("send_reply", {"body": "not ok"}, rules)
    assert ok is False
    assert "body" in reason
    assert "not ok" in reason


def test_in_rule_allows_listed_value():
    rules = {"send_reply": [ArgumentRule(field="to", operator="in", value=["a@x.com", "b@x.com"])]}
    ok, _ = match_arguments("send_reply", {"to": "b@x.com"}, rules)
    assert ok is True


def test_in_rule_denies_unlisted_value():
    rules = {"send_reply": [ArgumentRule(field="to", operator="in", value=["a@x.com"])]}
    ok, reason = match_arguments("send_reply", {"to": "evil@x.com"}, rules)
    assert ok is False
    assert "evil@x.com" in reason


def test_not_in_rule_denies_listed_value():
    rules = {"send_reply": [ArgumentRule(field="to", operator="not_in", value=["blocked@x.com"])]}
    ok, _ = match_arguments("send_reply", {"to": "blocked@x.com"}, rules)
    assert ok is False


def test_not_in_rule_allows_unlisted_value():
    rules = {"send_reply": [ArgumentRule(field="to", operator="not_in", value=["blocked@x.com"])]}
    ok, _ = match_arguments("send_reply", {"to": "fine@x.com"}, rules)
    assert ok is True


def test_regex_rule_allows_matching_value():
    rules = {"send_reply": [ArgumentRule(field="to", operator="regex", value=r".+@example\.com")]}
    ok, _ = match_arguments("send_reply", {"to": "person@example.com"}, rules)
    assert ok is True


def test_regex_rule_denies_non_matching_value():
    rules = {"send_reply": [ArgumentRule(field="to", operator="regex", value=r".+@example\.com")]}
    ok, _ = match_arguments("send_reply", {"to": "person@other.com"}, rules)
    assert ok is False


def test_missing_field_denies():
    rules = {"send_reply": [ArgumentRule(field="to", operator="equals", value="a@x.com")]}
    ok, reason = match_arguments("send_reply", {}, rules)
    assert ok is False
    assert "<missing>" in reason


def test_nested_dotted_field_resolves():
    rules = {"search": [ArgumentRule(field="filters.folder", operator="equals", value="inbox")]}
    ok, _ = match_arguments("search", {"filters": {"folder": "inbox"}}, rules)
    assert ok is True


def test_unconstrained_tool_always_passes():
    ok, reason = match_arguments("read_thread", {"anything": "goes"}, {})
    assert ok is True
    assert reason is None


def test_tool_with_no_rules_entry_always_passes():
    rules = {"send_reply": []}
    ok, _ = match_arguments("send_reply", {"body": "literally anything"}, rules)
    assert ok is True


def test_first_failing_rule_is_reported_when_multiple_rules_present():
    rules = {
        "send_reply": [
            ArgumentRule(field="to", operator="equals", value="a@x.com"),
            ArgumentRule(field="body", operator="equals", value="ok"),
        ]
    }
    ok, reason = match_arguments("send_reply", {"to": "wrong@x.com", "body": "ok"}, rules)
    assert ok is False
    assert "to" in reason


# --- TaskPolicy loading -------------------------------------------------------


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _valid_policy_dict():
    return {
        "subject": "demo-agent",
        "audience": "mail-server",
        "ttl_seconds": 300,
        "quota": 5,
        "grants": [
            {"tool": "read_thread"},
            {
                "tool": "send_reply",
                "arguments": [{"field": "to", "operator": "in", "value": ["a@x.com"]}],
            },
        ],
    }


def test_load_task_policy_from_json(tmp_path):
    path = _write(tmp_path, "policy.json", _valid_policy_dict())
    policy = load_task_policy(path)
    assert policy.subject == "demo-agent"
    assert policy.audience == "mail-server"
    assert policy.ttl_seconds == 300
    assert policy.quota == 5
    assert policy.tools == ("read_thread", "send_reply")
    assert policy.argument_constraints == {
        "send_reply": [ArgumentRule(field="to", operator="in", value=["a@x.com"])]
    }


def test_load_task_policy_tool_without_arguments_has_no_constraints(tmp_path):
    path = _write(tmp_path, "policy.json", _valid_policy_dict())
    policy = load_task_policy(path)
    assert "read_thread" not in policy.argument_constraints


@pytest.mark.parametrize("missing_field", ["subject", "audience", "ttl_seconds", "quota", "grants"])
def test_load_task_policy_rejects_missing_required_field(tmp_path, missing_field):
    data = _valid_policy_dict()
    del data[missing_field]
    path = _write(tmp_path, "policy.json", data)
    with pytest.raises(ValueError):
        load_task_policy(path)


def test_load_task_policy_rejects_grant_without_tool(tmp_path):
    data = _valid_policy_dict()
    data["grants"].append({"arguments": []})
    path = _write(tmp_path, "policy.json", data)
    with pytest.raises(ValueError):
        load_task_policy(path)


def test_load_task_policy_rejects_malformed_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_task_policy(path)


# --- validate_against_tools_list ---------------------------------------------


def test_validate_against_tools_list_passes_when_all_tools_known(tmp_path):
    path = _write(tmp_path, "policy.json", _valid_policy_dict())
    policy = load_task_policy(path)
    validate_against_tools_list(policy, {"read_thread", "send_reply", "draft_reply"})  # no raise


def test_validate_against_tools_list_fails_closed_on_unknown_tool(tmp_path):
    path = _write(tmp_path, "policy.json", _valid_policy_dict())
    policy = load_task_policy(path)
    with pytest.raises(ValueError, match="send_reply"):
        validate_against_tools_list(policy, {"read_thread"})
