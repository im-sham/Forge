"""Legacy Forge MCP HTTP launcher for private Hermes/Tailscale usage.

This module is intentionally kept as a compatibility bridge for existing
launchd/Tailscale setups. The tracked public entrypoint is:

    forge mcp serve

or:

    python -m forge_cli.mcp_http

Unlike the public entrypoint, this legacy wrapper keeps the historical
behavior of binding to 0.0.0.0 and disabling DNS rebinding protection.
Use it only on a trusted private network.
"""

from __future__ import annotations

from forge_cli.mcp_http import options_from_env, serve_mcp_http


def main() -> None:
    serve_mcp_http(
        options_from_env(
            default_host="0.0.0.0",
            default_port=8765,
            allow_remote=True,
            disable_dns_rebinding_protection=True,
        )
    )


if __name__ == "__main__":
    main()
