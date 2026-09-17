"""Synthetic target MCP server for the Covenant demo.

Exposes three tools over stdio: read_thread, draft_reply, send_reply. State
is in-memory and resets every process start -- this is demo data, not a real
mail system. send_reply just records that it "would have sent" something; it
never actually delivers anything anywhere, since the whole point of the demo
is that Covenant blocks it before it gets this far.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("mail-server")

_THREAD = [
    {"from": "alice@example.com", "body": "Can you review the Q3 numbers by Friday?"},
    {"from": "bob@example.com", "body": "Also loop in finance before you reply."},
]

_state = {"draft": None, "sent": []}


@server.tool()
def read_thread() -> str:
    """Read the full email thread."""
    return "\n".join(f"{m['from']}: {m['body']}" for m in _THREAD)


@server.tool()
def draft_reply(body: str) -> str:
    """Draft a reply without sending it."""
    _state["draft"] = body
    return f"Draft saved: {body!r}"


@server.tool()
def send_reply(body: str) -> str:
    """Send a reply. This is the tool Covenant should refuse when the human
    did not grant 'send' during consent."""
    _state["sent"].append(body)
    return f"Sent: {body!r}"


def main() -> None:
    import anyio

    anyio.run(server.run_stdio_async)


if __name__ == "__main__":
    main()
