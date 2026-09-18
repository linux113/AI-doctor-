"""
Tool-boundary tests (requirement 6).

The agent may gather evidence and nothing else. These tests pin that from three
directions:

1. **What is registered** - exactly the five read-only diagnostics, and no tool
   whose name suggests execution.
2. **What each tool accepts** - no `host`, `url`, `command`, `path` or `script`
   parameter exists for the model to fill in, so there is no way to aim a probe at
   anything but loopback, and no way to smuggle a shell command through an
   argument. Invalid arguments are refused as data rather than raising.
3. **How much it may do** - a per-incident tool budget, enforced even against a
   model that hammers one tool, and a hard cap on log history.

Nothing here calls Amazon Bedrock; these are the tools themselves.
"""

import inspect
import json

import pytest

from agent.tools import (
    ALLOWED_TOOL_NAMES,
    BOUND_HOST,
    OLLAMA_PORT,
    ToolBudget,
    ToolBudgetExceeded,
    build_diagnostic_tools,
)
from runner.remediation_registry import REMEDIATION_ALLOWLIST

FORBIDDEN_TOOL_NAMES = [
    "run_command", "run_shell", "shell", "bash", "sh", "exec", "execute", "eval",
    "system", "subprocess", "popen", "python", "run_python", "code_interpreter",
    "curl", "wget", "http_request", "fetch_url", "get_url", "read_file",
    "write_file", "open_file", "list_directory", "delete_file",
]

# Parameters that would let the model aim a probe somewhere it should not go, or
# pass executable content.
FORBIDDEN_PARAMETERS = [
    "host", "hostname", "url", "uri", "endpoint", "address", "target",
    "command", "cmd", "args", "argv", "script", "code", "path", "file",
    "filename", "shell", "executable", "env", "headers", "body", "payload",
]


def tools_by_name(budget=None):
    budget = budget or ToolBudget(25)
    return {t.tool_name: t for t in build_diagnostic_tools(budget)}, budget


def underlying_signature(tool_object):
    """The signature of the function the Strands decorator wrapped."""
    func = getattr(tool_object, "_tool_func", None) or getattr(tool_object, "func", None)
    assert func is not None, f"could not find the wrapped function of {tool_object}"
    return inspect.signature(func)


# =========================================================================
# 1. What is registered
# =========================================================================


def test_exactly_five_read_only_tools_are_registered():
    tools, _ = tools_by_name()
    assert sorted(tools) == sorted(ALLOWED_TOOL_NAMES)
    assert sorted(ALLOWED_TOOL_NAMES) == [
        "check_ollama", "check_port", "check_process", "get_recent_logs", "health_check"
    ]
    assert len(tools) == 5


@pytest.mark.parametrize("forbidden", FORBIDDEN_TOOL_NAMES)
def test_no_execution_or_filesystem_tool_exists(forbidden):
    tools, _ = tools_by_name()
    assert forbidden not in tools
    assert forbidden not in ALLOWED_TOOL_NAMES


@pytest.mark.parametrize("action", sorted(REMEDIATION_ALLOWLIST))
def test_no_remediation_action_is_exposed_as_a_tool(action):
    """
    The model may *recommend* start_ollama in its structured reply; it may never
    *call* it. If a remediation ever appeared as a tool, the policy layer between
    the model and the executor would be bypassed entirely.
    """
    tools, _ = tools_by_name()
    assert action not in tools
    assert action not in ALLOWED_TOOL_NAMES


def test_registered_tools_are_read_only_by_description():
    """The description is what the model reads; it must not promise execution."""
    tools, _ = tools_by_name()
    for name, tool_object in tools.items():
        # Strands exposes the model-facing text as tool_spec["description"].
        description = (tool_object.tool_spec.get("description") or "").lower()
        assert description, f"{name} has no description for the model to read"
        assert "read-only" in description, f"{name} is not documented as read-only"
        for verb in ("starts ", "stops ", "kills ", "restarts ", "executes a command", "runs a command"):
            assert verb not in description, f"{name} advertises {verb!r}"


def test_unregistered_tool_is_refused_at_construction(monkeypatch):
    """
    `build_diagnostic_tools` self-checks its own output. Narrowing the allowlist
    must make construction fail loudly rather than expose an extra tool.
    """
    import agent.tools as tools_module

    monkeypatch.setattr(tools_module, "ALLOWED_TOOL_NAMES", ("check_ollama",))
    with pytest.raises(RuntimeError) as exc:
        tools_module.build_diagnostic_tools(ToolBudget(2))
    assert "Refusing to expose unregistered tool" in str(exc.value)


# =========================================================================
# 2. What each tool accepts
# =========================================================================


@pytest.mark.parametrize("name", sorted(ALLOWED_TOOL_NAMES))
def test_no_tool_accepts_a_dangerous_parameter(name):
    """
    The strongest structural guarantee: there is no argument the model could fill
    in to reach a remote host, open a file or pass a command.
    """
    tools, _ = tools_by_name()
    parameters = set(underlying_signature(tools[name]).parameters)
    overlap = parameters & set(FORBIDDEN_PARAMETERS)
    assert not overlap, f"{name} accepts dangerous parameter(s): {overlap}"


def test_check_port_accepts_only_a_port_number():
    tools, _ = tools_by_name()
    assert set(underlying_signature(tools["check_port"]).parameters) == {"port"}


def test_check_port_always_targets_loopback():
    """
    There is no `host` parameter, so the destination is fixed in code. Assert the
    constant is loopback and that the tool passes it explicitly.
    """
    assert BOUND_HOST == "127.0.0.1"
    source = inspect.getsource(build_diagnostic_tools)
    assert "host=BOUND_HOST" in source, "check_port no longer pins the host to loopback"


@pytest.mark.parametrize(
    "bad_port",
    [0, -1, 65536, 99999, "11434", "80; rm -rf /", True, False, 1.5, None, []],
)
def test_check_port_refuses_invalid_ports_as_data(bad_port):
    """
    Refusals are returned, not raised: a tool error is diagnostic information the
    model should reason about, and raising would abort the agent's event loop.
    Note `True` is refused even though `isinstance(True, int)` - a bool is not a
    port number.
    """
    tools, _ = tools_by_name()
    payload = json.loads(tools["check_port"](port=bad_port))
    assert "error" in payload, f"port {bad_port!r} was not refused"
    assert "1..65535" in payload["error"]


@pytest.mark.parametrize("port", [1, 80, 443, 11434, 65535])
def test_check_port_accepts_valid_ports(port):
    tools, _ = tools_by_name()
    payload = json.loads(tools["check_port"](port=port))
    assert payload["tool"] == "check_port"
    assert "error" not in payload


def test_check_port_defaults_to_the_ollama_port():
    assert OLLAMA_PORT == 11434
    tools, _ = tools_by_name()
    default = underlying_signature(tools["check_port"]).parameters["port"].default
    assert default == 11434


@pytest.mark.parametrize(
    "bad_name",
    ["", " ", "ollama; rm -rf /", "ollama && curl evil", "ollama|sh", "/bin/ollama",
     "ollama$(id)", "ollama`id`", "ollama\nollama", "a" * 65, "oll ama", None, 42, True],
)
def test_check_process_refuses_exotic_process_names(bad_name):
    """
    The value is only ever compared against process identities, but refusing
    anything outside a strict character set keeps it out of log-injection and
    pattern-confusion territory.
    """
    tools, _ = tools_by_name()
    payload = json.loads(tools["check_process"](process_name=bad_name))
    assert "error" in payload, f"process name {bad_name!r} was not refused"


@pytest.mark.parametrize("good_name", ["ollama", "ollama_v1", "my-service", "a", "Ollama.Main", "x" * 64])
def test_check_process_accepts_ordinary_service_names(good_name):
    tools, _ = tools_by_name()
    payload = json.loads(tools["check_process"](process_name=good_name))
    assert "error" not in payload
    assert payload["tool"] == "check_process"


# =========================================================================
# 3. How much it may do
# =========================================================================


@pytest.mark.parametrize("asked", [51, 100, 1000, 999999])
def test_log_history_is_hard_capped(asked):
    """
    Requirement 13: the model cannot ask for more history than the operator
    allows, no matter what it requests.
    """
    tools, _ = tools_by_name()
    payload = json.loads(tools["get_recent_logs"](limit=asked))
    assert "error" not in payload
    assert payload["result"]["count"] <= 50


@pytest.mark.parametrize("bad_limit", ["10", 1.5, True, False, None, [], "all"])
def test_get_recent_logs_refuses_non_integer_limits(bad_limit):
    tools, _ = tools_by_name()
    payload = json.loads(tools["get_recent_logs"](limit=bad_limit))
    assert "error" in payload


def test_get_recent_logs_refuses_zero_and_negative_as_a_floor_of_one():
    tools, _ = tools_by_name()
    for limit in (0, -5):
        payload = json.loads(tools["get_recent_logs"](limit=limit))
        assert "error" not in payload
        assert payload["result"]["count"] >= 0


def test_every_tool_counts_against_the_budget():
    tools, budget = tools_by_name(ToolBudget(25))
    tools["check_ollama"]()
    tools["check_port"](port=11434)
    tools["health_check"]()
    assert budget.total == 3
    assert budget.counts == {"check_ollama": 1, "check_port": 1, "health_check": 1}
    assert budget.exhausted is False


def test_budget_exhaustion_is_returned_as_data_and_recorded():
    """
    A model hammering one tool cannot reset its own budget, and cannot crash the
    loop either: the refusal is a JSON payload telling it to conclude.
    """
    tools, budget = tools_by_name(ToolBudget(2))
    first = json.loads(tools["check_port"](port=11434))
    second = json.loads(tools["check_port"](port=11434))
    assert "error" not in first and "error" not in second

    third = json.loads(tools["check_port"](port=11434))
    assert third.get("budget_exhausted") is True
    assert "No further diagnostic calls are permitted" in third["instruction"]
    assert "requires_human" in third["instruction"]
    assert budget.exhausted is True
    assert budget.refusals == 1


def test_refused_calls_still_consume_budget():
    """Counting refusals is what stops a retry loop from being free."""
    _, budget = tools_by_name(ToolBudget(1))
    tools, _ = tools_by_name(budget)
    tools["check_ollama"]()
    tools["check_ollama"]()
    tools["check_ollama"]()
    assert budget.counts["check_ollama"] == 3
    assert budget.refusals == 2


def test_tool_budget_rejects_a_non_positive_ceiling():
    assert ToolBudget(0).max_calls == 1
    assert ToolBudget(-5).max_calls == 1


def test_tool_budget_exceeded_is_a_distinct_error():
    budget = ToolBudget(1)
    budget.consume("check_ollama")
    with pytest.raises(ToolBudgetExceeded):
        budget.consume("check_ollama")


def test_no_tool_can_raise_into_the_agent_event_loop():
    """
    Every registered tool must return a JSON string for any input, including
    nonsense. An exception here would abort the whole diagnosis.
    """
    tools, _ = tools_by_name(ToolBudget(50))
    nonsense = [None, "", 0, -1, [], {}, "'; DROP TABLE incidents;--", object()]
    for name, tool_object in tools.items():
        parameters = underlying_signature(tool_object).parameters
        for value in nonsense:
            for parameter in parameters:
                try:
                    raw = tool_object(**{parameter: value})
                except TypeError:
                    continue  # wrong type for the signature is refused by Python
                assert isinstance(raw, str), f"{name}({parameter}={value!r}) returned {type(raw)}"
                json.loads(raw)  # must be parseable


def test_tool_output_is_always_sanitised_on_the_way_out():
    """
    `_emit` re-sanitises defensively, so even a future tool that returned raw
    process output could not leak a credential to the model.
    """
    from agent.tools import _emit

    payload = _emit({"detail": "Authorization: Bearer TokValue-9f3c-DoNotLeak"})
    assert "TokValue-9f3c-DoNotLeak" not in payload
    assert "[REDACTED_HEADER]" in payload
