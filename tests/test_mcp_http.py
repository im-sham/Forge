import pytest


mcp = pytest.importorskip("mcp")

from forge_cli.mcp_http import (  # noqa: E402
    MCPHTTPServerOptions,
    resolve_transport_security,
    validate_server_options,
)


def test_validate_server_options_allows_loopback_defaults():
    validate_server_options(MCPHTTPServerOptions())


def test_validate_server_options_rejects_remote_bind_without_opt_in():
    options = MCPHTTPServerOptions(host="0.0.0.0")

    with pytest.raises(ValueError, match="--allow-remote"):
        validate_server_options(options)


def test_validate_server_options_requires_explicit_dns_override_for_remote_bind():
    options = MCPHTTPServerOptions(host="0.0.0.0", allow_remote=True)

    with pytest.raises(ValueError, match="--disable-dns-rebinding-protection"):
        validate_server_options(options)


def test_resolve_transport_security_keeps_localhost_protection_enabled():
    security = resolve_transport_security(MCPHTTPServerOptions())

    assert security is not None
    assert security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in security.allowed_hosts


def test_resolve_transport_security_can_disable_protection_for_private_network_use():
    security = resolve_transport_security(
        MCPHTTPServerOptions(
            host="0.0.0.0",
            allow_remote=True,
            disable_dns_rebinding_protection=True,
        )
    )

    assert security is not None
    assert security.enable_dns_rebinding_protection is False
