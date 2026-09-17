"""The Covenant MCP proxy.

Sits between an upstream MCP client (Claude Desktop / Gemini CLI, talking
stdio on our stdin/stdout) and a downstream target MCP server (launched as a
subprocess, talking stdio to us as its parent). Every `tools/call` from the
upstream client is checked against the active capability via the broker
before being forwarded downstream; every other request type (tools/list,
initialize, ...) passes through untouched via thin delegating handlers.

Startup sequence:
  1. Launch the target server subprocess, initialize the downstream session,
     fetch its real tool list.
  2. Run consent: a human approves a subset of those tools, a TTL, a quota.
  3. Mint a signed capability for exactly what was approved.
  4. Serve the upstream leg, routing tools/call through Broker.authorize()
     and logging every decision to the audit log.
"""

from __future__ import annotations

import sys

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from covenant import config
from covenant.audit import AuditLog
from covenant.broker import Broker, Decision
from covenant.capability import SignedCapability
from covenant.consent import (
    DEFAULT_WEB_CONSENT_TIMEOUT_SECONDS,
    ConsentDecision,
    ConsentProvider,
    ConsentRequest,
    ScriptedConsentProvider,
    select_consent_provider,
)
from covenant.issuer import Issuer
from covenant.merkle import MerkleAuditLog
from covenant.policy import TaskPolicy, load_task_policy, validate_against_tools_list


class CovenantProxy:
    def __init__(
        self,
        target_command: str,
        target_args: list[str],
        *,
        audience: str,
        subject: str = config.DEFAULT_SUBJECT,
        ttl_seconds: int = config.DEFAULT_TTL_SECONDS,
        quota: int = config.DEFAULT_QUOTA,
        consent_provider: ConsentProvider | None = None,
        task_policy: TaskPolicy | None = None,
    ):
        self._target_params = StdioServerParameters(command=target_command, args=target_args)
        self._audience = audience
        self._subject = subject
        self._ttl_seconds = ttl_seconds
        self._quota = quota
        self._consent_provider = consent_provider or select_consent_provider(auto=False)
        self._task_policy = task_policy

        self._audit_log = AuditLog(config.AUDIT_LOG_PATH)
        private_key = config.load_or_create_issuer_key()
        self._issuer = Issuer(private_key, config.ISSUER_KEY_ID, self._audit_log)
        self._merkle_log = MerkleAuditLog(self._audit_log, private_key, config.ISSUER_KEY_ID)
        self._broker = Broker()

        self._downstream: ClientSession | None = None
        self._active_grant: SignedCapability | None = None

    async def _establish_grant(self) -> None:
        assert self._downstream is not None
        tool_list = await self._downstream.list_tools()
        available_tools = {t.name for t in tool_list.tools}

        subject = self._subject
        ttl_seconds = self._ttl_seconds
        quota = self._quota
        argument_constraints: dict = {}

        if self._task_policy is not None:
            if self._task_policy.audience != self._audience:
                raise ValueError(
                    f"Task policy audience {self._task_policy.audience!r} does not match "
                    f"this proxy's audience {self._audience!r} -- refusing to start."
                )
            # Fails closed: a policy naming a tool the live server doesn't
            # actually offer must stop startup, not silently under-enforce.
            validate_against_tools_list(self._task_policy, available_tools)
            requested_tools = list(self._task_policy.tools)
            subject = self._task_policy.subject
            ttl_seconds = self._task_policy.ttl_seconds
            quota = self._task_policy.quota
            argument_constraints = self._task_policy.argument_constraints
        else:
            requested_tools = [t.name for t in tool_list.tools]

        decision = self._consent_provider.request_consent(
            ConsentRequest(
                subject=subject,
                audience=self._audience,
                requested_tools=requested_tools,
                ttl_seconds=ttl_seconds,
                quota=quota,
                argument_constraints=argument_constraints,
            )
        )
        if not decision.approved:
            print("Consent denied -- no capability issued. Every tool call will be refused.", file=sys.stderr)
            self._active_grant = None
            return

        granted_constraints = {
            tool: rules for tool, rules in argument_constraints.items() if tool in decision.granted_tools
        }
        self._active_grant = self._issuer.mint(
            subject=subject,
            audience=self._audience,
            tools=decision.granted_tools,
            ttl_seconds=decision.ttl_seconds,
            quota=decision.quota,
            argument_constraints=granted_constraints,
        )

    async def _on_list_tools(self, ctx, params):
        assert self._downstream is not None
        return await self._downstream.list_tools(params=params)

    async def _on_call_tool(self, ctx, params: types.CallToolRequestParams):
        assert self._downstream is not None

        if self._active_grant is None:
            reason = "No active capability -- consent was not granted."
            self._audit_log.append(
                event_type="tool_call",
                subject=self._subject,
                tool_name=params.name,
                decision=Decision.DENY.value,
                reason=reason,
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=reason)], is_error=True)

        result = self._broker.authorize(
            self._active_grant,
            tool_name=params.name,
            audience=self._audience,
            arguments=params.arguments or {},
        )
        self._audit_log.append(
            event_type="tool_call",
            grant_id=result.grant_id,
            subject=self._subject,
            tool_name=params.name,
            decision=result.decision.value,
            reason=result.reason,
        )

        if result.decision is Decision.DENY:
            print(f"DENIED  tool={params.name!r}  reason={result.reason}", file=sys.stderr)
            return types.CallToolResult(content=[types.TextContent(type="text", text=result.reason)], is_error=True)

        print(f"ALLOWED tool={params.name!r}  remaining_quota={result.remaining_quota}", file=sys.stderr)
        return await self._downstream.call_tool(params.name, params.arguments)

    async def run(self) -> None:
        async with stdio_client(self._target_params) as (down_read, down_write):
            async with ClientSession(down_read, down_write) as downstream:
                await downstream.initialize()
                self._downstream = downstream

                await self._establish_grant()

                upstream = Server(
                    "covenant-proxy",
                    on_list_tools=self._on_list_tools,
                    on_call_tool=self._on_call_tool,
                )

                async with stdio_server() as (up_read, up_write):
                    await upstream.run(up_read, up_write, upstream.create_initialization_options())


def run() -> None:
    """Entry point: `covenant-proxy [--auto] [--ttl SECONDS] [--web-consent-timeout SECONDS] [--policy PATH] <target_command> [target_args...]`.

    --auto skips consent entirely and applies the same read+draft/no-send
    policy a human would land on by accepting the defaults (see
    consent.default_demo_decision) -- for unattended demo/CI runs only.

    Without --auto, consent.select_consent_provider() picks the right surface
    automatically: a real console -> interactive terminal prompt; no console
    attached (e.g. launched by Claude Desktop as a GUI child process) -> a
    one-shot local browser consent page on 127.0.0.1, bounded by
    --web-consent-timeout (default 300s), denying if it's never answered.

    --policy PATH loads a declarative TaskPolicy (JSON, or YAML if PyYAML is
    installed -- see policy.py) that scopes exactly which tools, and which
    arguments to those tools, will even be offered for consent. The policy's
    own `audience` field becomes this proxy's audience (so the same CLI works
    against any MCP server, not just the "mail-server" demo default used when
    --policy is omitted). Startup fails closed if the policy names a tool the
    live target server doesn't actually offer.

    Example (wired into Claude Desktop / Gemini CLI config):
        covenant-proxy python demo/synthetic_mcp_server.py
    Example (policy-scoped):
        covenant-proxy --policy examples/read-only-email.json python demo/synthetic_mcp_server.py
    """
    args = sys.argv[1:]
    auto = "--auto" in args
    if auto:
        args.remove("--auto")

    ttl_seconds = config.DEFAULT_TTL_SECONDS
    if "--ttl" in args:
        idx = args.index("--ttl")
        ttl_seconds = int(args[idx + 1])
        del args[idx : idx + 2]

    web_consent_timeout_seconds = DEFAULT_WEB_CONSENT_TIMEOUT_SECONDS
    if "--web-consent-timeout" in args:
        idx = args.index("--web-consent-timeout")
        web_consent_timeout_seconds = int(args[idx + 1])
        del args[idx : idx + 2]

    task_policy = None
    if "--policy" in args:
        idx = args.index("--policy")
        task_policy = load_task_policy(args[idx + 1])
        del args[idx : idx + 2]

    if len(args) < 1:
        print(
            "usage: covenant-proxy [--auto] [--ttl SECONDS] [--web-consent-timeout SECONDS] "
            "[--policy PATH] <target_command> [target_args...]",
            file=sys.stderr,
        )
        raise SystemExit(2)

    target_command, *target_args = args
    if auto and task_policy is not None:
        # A policy file is itself the already-authored/reviewed request --
        # --auto here means "don't also stop for an interactive click," not
        # "fall back to the unrelated hardcoded demo default_demo_decision,"
        # which only knows about the 3 demo tool names and would otherwise
        # silently deny anything the policy asked for beyond read+draft.
        consent_provider = ScriptedConsentProvider(
            lambda req: ConsentDecision(
                approved=True,
                granted_tools=req.requested_tools,
                ttl_seconds=req.ttl_seconds,
                quota=req.quota,
            )
        )
    else:
        consent_provider = select_consent_provider(auto=auto, web_timeout_seconds=web_consent_timeout_seconds)
    proxy = CovenantProxy(
        target_command,
        target_args,
        audience=task_policy.audience if task_policy else "mail-server",
        ttl_seconds=ttl_seconds,
        consent_provider=consent_provider,
        task_policy=task_policy,
    )
    anyio.run(proxy.run)


if __name__ == "__main__":
    run()
