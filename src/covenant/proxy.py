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
    ConsentProvider,
    ConsentRequest,
    ScriptedConsentProvider,
    TerminalConsentProvider,
    default_demo_decision,
)
from covenant.issuer import Issuer
from covenant.merkle import MerkleAuditLog


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
    ):
        self._target_params = StdioServerParameters(command=target_command, args=target_args)
        self._audience = audience
        self._subject = subject
        self._ttl_seconds = ttl_seconds
        self._quota = quota
        self._consent_provider = consent_provider or TerminalConsentProvider()

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
        requested_tools = [t.name for t in tool_list.tools]

        decision = self._consent_provider.request_consent(
            ConsentRequest(
                subject=self._subject,
                audience=self._audience,
                requested_tools=requested_tools,
                ttl_seconds=self._ttl_seconds,
                quota=self._quota,
            )
        )
        if not decision.approved:
            print("Consent denied -- no capability issued. Every tool call will be refused.", file=sys.stderr)
            self._active_grant = None
            return

        self._active_grant = self._issuer.mint(
            subject=self._subject,
            audience=self._audience,
            tools=decision.granted_tools,
            ttl_seconds=decision.ttl_seconds,
            quota=decision.quota,
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

        result = self._broker.authorize(self._active_grant, tool_name=params.name, audience=self._audience)
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
    """Entry point: `covenant-proxy [--auto] [--ttl SECONDS] <target_command> [target_args...]`.

    --auto skips the interactive console prompt and applies the same
    read+draft/no-send policy a human would land on by pressing Enter
    (see consent.default_demo_decision) -- for unattended demo/CI runs only.

    Example (wired into Claude Desktop / Gemini CLI config):
        covenant-proxy python demo/synthetic_mcp_server.py
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

    if len(args) < 1:
        print("usage: covenant-proxy [--auto] [--ttl SECONDS] <target_command> [target_args...]", file=sys.stderr)
        raise SystemExit(2)

    target_command, *target_args = args
    consent_provider = ScriptedConsentProvider(default_demo_decision) if auto else TerminalConsentProvider()
    proxy = CovenantProxy(
        target_command,
        target_args,
        audience="mail-server",
        ttl_seconds=ttl_seconds,
        consent_provider=consent_provider,
    )
    anyio.run(proxy.run)


if __name__ == "__main__":
    run()
