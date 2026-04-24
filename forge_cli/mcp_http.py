"""Forge MCP HTTP server.

Canonical Streamable HTTP entrypoint for exposing Forge over MCP.
Defaults are local-only and keep DNS rebinding protection enabled.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

from mcp.server.fastmcp.server import TransportSecuritySettings

from forge_cli.mcp_server import mcp


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


@dataclass(frozen=True)
class MCPHTTPServerOptions:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    allow_remote: bool = False
    disable_dns_rebinding_protection: bool = False


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized in {"127.0.0.1", "localhost", "::1"}:
        return True

    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_server_options(options: MCPHTTPServerOptions) -> None:
    """Reject network-exposed binds unless the caller opts in explicitly."""
    if _is_loopback_host(options.host):
        return

    if not options.allow_remote:
        raise ValueError(
            f"Refusing to bind Forge MCP HTTP server to '{options.host}' without --allow-remote. "
            "Use the local default or explicitly opt into remote access on a trusted network."
        )

    if not options.disable_dns_rebinding_protection:
        raise ValueError(
            f"Remote host '{options.host}' requires --disable-dns-rebinding-protection. "
            "Keep the default local bind unless you intentionally trust the surrounding network."
        )


def resolve_transport_security(
    options: MCPHTTPServerOptions,
) -> TransportSecuritySettings | None:
    """Return the transport security config for the requested bind mode."""
    if options.disable_dns_rebinding_protection:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)

    if _is_loopback_host(options.host):
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        )

    return None


def configure_mcp_http(options: MCPHTTPServerOptions) -> None:
    """Apply runtime options to the shared FastMCP instance."""
    validate_server_options(options)
    mcp.settings.host = options.host
    mcp.settings.port = options.port
    mcp.settings.transport_security = resolve_transport_security(options)


def serve_mcp_http(options: MCPHTTPServerOptions) -> None:
    """Run Forge over the MCP Streamable HTTP transport."""
    configure_mcp_http(options)
    mcp.run(transport="streamable-http")


def options_from_env(
    *,
    default_host: str = DEFAULT_HOST,
    default_port: int = DEFAULT_PORT,
    allow_remote: bool = False,
    disable_dns_rebinding_protection: bool = False,
) -> MCPHTTPServerOptions:
    """Build server options from environment variables with explicit defaults."""
    host = os.getenv("FORGE_MCP_HOST", default_host)
    port = int(os.getenv("FORGE_MCP_PORT", str(default_port)))
    return MCPHTTPServerOptions(
        host=host,
        port=port,
        allow_remote=allow_remote,
        disable_dns_rebinding_protection=disable_dns_rebinding_protection,
    )


def main() -> None:
    """Module entrypoint for local-only HTTP serving."""
    serve_mcp_http(options_from_env())


if __name__ == "__main__":
    main()
