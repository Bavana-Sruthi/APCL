"""Drives the live Covenant proxy over real stdio, standing in for Claude
Desktop / Gemini CLI for demo and CI purposes.

This is the mechanism behind scripts/demo.sh: it launches `covenant-proxy
--auto` (auto-consent to the same read+draft/no-send policy a human would
approve by pressing Enter), talks real MCP to it, and narrates the two
critical demo beats:
  1. read_thread and draft_reply succeed; send_reply is denied with a reason.
  2. after the (short, real) TTL expires, replaying send_reply is denied
     because the capability is dead -- not because it was denied by scope.

Nothing here is scripted at the enforcement layer: the proxy, broker, and
issuer are the exact same code a real agent client would drive. Only the
"agent's" sequence of actions and the human's consent are pre-recorded.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parent.parent


def _proxy_params(ttl_seconds: int) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "covenant.proxy",
            "--auto",
            "--ttl",
            str(ttl_seconds),
            sys.executable,
            str(ROOT / "demo" / "synthetic_mcp_server.py"),
        ],
        cwd=str(ROOT),
    )


async def _call(session: ClientSession, tool: str, **arguments) -> None:
    result = await session.call_tool(tool, arguments)
    text = result.content[0].text if result.content else ""
    tag = "DENIED " if result.is_error else "ALLOWED"
    print(f"{tag} {tool:<12} -> {text}")


async def run_beats_1_and_2(ttl_seconds: int) -> None:
    print(f"=== Beat 1-2: grant, allowed calls, out-of-scope denial (TTL={ttl_seconds}s) ===")
    async with stdio_client(_proxy_params(ttl_seconds)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await _call(session, "read_thread")
            await _call(session, "draft_reply", body="Sounds good, will follow up Friday.")
            await _call(session, "send_reply", body="Sounds good, will follow up Friday.")

            print(f"--- waiting {ttl_seconds + 1}s for the capability to expire ---")
            await asyncio.sleep(ttl_seconds + 1)

            print("=== Beat 3: replay after expiry ===")
            await _call(session, "send_reply", body="Sounds good, will follow up Friday.")


def main() -> None:
    ttl_seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    asyncio.run(run_beats_1_and_2(ttl_seconds))


if __name__ == "__main__":
    main()
