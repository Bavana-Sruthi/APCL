"""Drives the live Covenant proxy in --policy mode over real stdio, standing
in for Claude Desktop / Gemini CLI -- the argument-scoping counterpart to
scripted_client.py.

Launches `covenant-proxy --auto --policy examples/read-only-email.json`
against the real demo server and narrates the argument-scoping beat that
tool-name-only scoping (scripted_client.py) can't show:
  1. read_thread / draft_reply succeed (unconstrained by the policy).
  2. send_reply with an unapproved reply body is DENIED, even though
     send_reply itself is a granted tool -- only this specific argument
     value is out of scope.
  3. send_reply with the exact pre-approved reply body is ALLOWED.

Nothing here is scripted at the enforcement layer: the proxy, broker, and
issuer are the exact same code a real agent client would drive. Only the
"agent's" sequence of actions and the human's consent (via --auto, honoring
the policy file) are pre-recorded.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parent.parent
APPROVED_BODY = "Thanks, I'll review and get back to you by Friday."


def _proxy_params(policy_path: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "covenant.proxy",
            "--auto",
            "--policy",
            str(policy_path),
            sys.executable,
            str(ROOT / "demo" / "synthetic_mcp_server.py"),
        ],
        cwd=str(ROOT),
    )


async def _call(session: ClientSession, tool: str, **arguments) -> None:
    result = await session.call_tool(tool, arguments)
    text = result.content[0].text if result.content else ""
    tag = "DENIED " if result.is_error else "ALLOWED"
    print(f"{tag} {tool:<12} args={arguments} -> {text}")


async def run_policy_demo(policy_path: Path) -> None:
    print(f"=== Argument-scoped policy demo (policy={policy_path.name}) ===")
    async with stdio_client(_proxy_params(policy_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await _call(session, "read_thread")
            await _call(session, "draft_reply", body="draft text, never sent")

            print("--- send_reply with an unapproved body: expect DENIED ---")
            await _call(session, "send_reply", body="some other unapproved text")

            print("--- send_reply with the exact pre-approved body: expect ALLOWED ---")
            await _call(session, "send_reply", body=APPROVED_BODY)


def main() -> None:
    policy_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "examples" / "read-only-email.json"
    asyncio.run(run_policy_demo(policy_path))


if __name__ == "__main__":
    main()
