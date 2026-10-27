"""Unit tests for TargetManager URL normalization, validation, and authorization."""

import pytest

from lume.core.target_manager.manager import (
    TargetAuthorizationError,
    TargetManager,
    TargetValidationError,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def validate(url):
    """Convenience wrapper so tests read as assertions about the return value."""
    return TargetManager.validate_target_url(url)


def raises_validation(url):
    """Return True when validate_target_url raises TargetValidationError."""
    with pytest.raises(TargetValidationError):
        TargetManager.validate_target_url(url)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Normalization — scheme-less inputs default to HTTPS
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalization:
    def test_bare_domain_defaults_to_https(self):
        assert validate("example.com") == "https://example.com"

    def test_www_hostname_defaults_to_https(self):
        assert validate("www.example.com") == "https://www.example.com"

    def test_hostname_with_port_defaults_to_https(self):
        assert validate("example.com:8443") == "https://example.com:8443"

    def test_localhost_with_port_defaults_to_https(self):
        assert validate("localhost:8000/v1/chat") == "https://localhost:8000/v1/chat"

    def test_hostname_with_path_defaults_to_https(self):
        assert validate("example.com/api/v1") == "https://example.com/api/v1"

    def test_hostname_with_path_and_query_defaults_to_https(self):
        assert validate("example.com/api?model=test") == "https://example.com/api?model=test"

    def test_explicit_https_preserved(self):
        assert validate("https://example.com/api") == "https://example.com/api"

    def test_explicit_http_preserved(self):
        """http:// must not be silently upgraded to https://."""
        assert validate("http://localhost:8000/chat") == "http://localhost:8000/chat"

    def test_explicit_http_external_preserved(self):
        assert validate("http://example.com/path") == "http://example.com/path"

    def test_surrounding_whitespace_stripped(self):
        assert validate("  https://example.com/api  ") == "https://example.com/api"

    def test_scheme_less_whitespace_stripped_then_https(self):
        assert validate("  example.com  ") == "https://example.com"

    def test_fragment_preserved(self):
        result = validate("https://example.com/path#section")
        assert result == "https://example.com/path#section"

    def test_query_and_fragment_preserved(self):
        result = validate("example.com/path?a=1&b=2#anchor")
        assert result == "https://example.com/path?a=1&b=2#anchor"

    def test_numeric_ip_defaults_to_https(self):
        assert validate("192.168.1.1:8080/v1") == "https://192.168.1.1:8080/v1"


# ─────────────────────────────────────────────────────────────────────────────
# Validation failures
# ─────────────────────────────────────────────────────────────────────────────

class TestValidationFailures:
    def test_empty_string_rejected(self):
        assert raises_validation("")

    def test_whitespace_only_rejected(self):
        assert raises_validation("   ")

    def test_none_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.validate_target_url(None)  # type: ignore[arg-type]

    def test_integer_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.validate_target_url(12345)  # type: ignore[arg-type]

    def test_list_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.validate_target_url(["http://example.com"])  # type: ignore[arg-type]

    def test_ftp_scheme_rejected(self):
        assert raises_validation("ftp://example.com")

    def test_ws_scheme_rejected(self):
        assert raises_validation("ws://example.com/socket")

    def test_file_scheme_rejected(self):
        assert raises_validation("file:///etc/passwd")

    def test_missing_host_after_scheme_rejected(self):
        assert raises_validation("https://")

    def test_missing_host_after_scheme_with_slash_rejected(self):
        assert raises_validation("https:///path")

    def test_invalid_non_numeric_port_rejected(self):
        """example.com:abc must be rejected — port is not numeric."""
        assert raises_validation("https://example.com:abc")

    def test_invalid_non_numeric_port_schemeless_rejected(self):
        assert raises_validation("example.com:abc/path")

    def test_port_zero_rejected(self):
        assert raises_validation("https://example.com:0/path")

    def test_port_above_max_rejected(self):
        assert raises_validation("https://example.com:65536/path")

    def test_hostname_with_internal_whitespace_rejected(self):
        assert raises_validation("https://bad host.com/path")

    def test_schemeless_hostname_with_space_rejected(self):
        assert raises_validation("bad host.com")


# ─────────────────────────────────────────────────────────────────────────────
# Authorization — normalization must never implicitly authorize
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthorization:
    def test_normalized_external_host_requires_authorization(self):
        """A bare hostname normalized to https:// must still need --authorized."""
        with pytest.raises(TargetAuthorizationError):
            TargetManager.create_target_config(
                endpoint="example.com",
                authorized=False,
            )

    def test_normalized_external_host_accepted_when_authorized(self):
        """Explicit --authorized allows an external target after normalization."""
        config = TargetManager.create_target_config(
            endpoint="example.com",
            authorized=True,
        )
        assert config.endpoint == "https://example.com"

    def test_localhost_http_auto_authorized(self):
        """localhost with explicit http:// remains auto-authorized (existing behavior)."""
        config = TargetManager.create_target_config(
            endpoint="http://localhost:8000/v1/chat",
            authorized=False,
        )
        assert config.endpoint == "http://localhost:8000/v1/chat"

    def test_localhost_schemeless_auto_authorized(self):
        """localhost without a scheme is normalized to https and auto-authorized."""
        config = TargetManager.create_target_config(
            endpoint="localhost:8000/v1/chat",
            authorized=False,
        )
        assert config.endpoint == "https://localhost:8000/v1/chat"

    def test_loopback_ip_auto_authorized(self):
        config = TargetManager.create_target_config(
            endpoint="http://127.0.0.1:9090/chat",
            authorized=False,
        )
        assert config.endpoint == "http://127.0.0.1:9090/chat"

    def test_normalization_does_not_set_authorized_flag(self):
        """create_target_config must raise even after successful normalization for external hosts."""
        with pytest.raises(TargetAuthorizationError):
            TargetManager.create_target_config(
                endpoint="www.external-ai-service.com/api",
                authorized=False,
            )

    def test_external_https_without_authorized_rejected(self):
        with pytest.raises(TargetAuthorizationError):
            TargetManager.create_target_config(
                endpoint="https://ai-staging.client.com/v1/chat",
                authorized=False,
            )

    def test_external_https_with_authorized_accepted(self):
        config = TargetManager.create_target_config(
            endpoint="https://ai-staging.client.com/v1/chat",
            authorized=True,
        )
        assert config.endpoint == "https://ai-staging.client.com/v1/chat"


# ─────────────────────────────────────────────────────────────────────────────
# Regression — existing valid URLs and config fields must be intact
# ─────────────────────────────────────────────────────────────────────────────

class TestRegression:
    def test_full_localhost_url_unchanged(self):
        assert validate("http://localhost:8000/v1/chat") == "http://localhost:8000/v1/chat"

    def test_https_with_path_and_query_unchanged(self):
        url = "https://example.com/path?a=1"
        assert validate(url) == url

    def test_create_target_config_preserves_all_fields(self):
        """All TargetConfig fields set via create_target_config must be preserved."""
        config = TargetManager.create_target_config(
            endpoint="http://localhost:9000/chat",
            adapter_type="http",
            timeout=15.0,
            headers={"X-Test": "yes"},
            model_name="gpt-4o",
            authorized=False,
            proxy="http://127.0.0.1:8080",
            verify=False,
            cert="/tmp/client.pem",
            delay_ms=200,
            user_agent="TestAgent/1.0",
        )
        assert config.endpoint == "http://localhost:9000/chat"
        assert config.adapter_type == "http"
        assert config.timeout == 15.0
        assert config.headers == {"X-Test": "yes"}
        assert config.model_name == "gpt-4o"
        assert config.proxy == "http://127.0.0.1:8080"
        assert config.verify is False
        assert config.cert == "/tmp/client.pem"
        assert config.delay_ms == 200
        assert config.user_agent == "TestAgent/1.0"

    def test_validate_does_not_mutate_valid_https_url(self):
        url = "https://example.com/api/v2?key=abc&flag=true"
        assert validate(url) == url

    def test_test_fixture_hostnames_auto_authorized(self):
        """Synthetic test-fixture hostnames must remain auto-authorized (existing behavior)."""
        for hostname in ("vulnerable-ai", "protected-ai", "test-ai"):
            config = TargetManager.create_target_config(
                endpoint=f"http://{hostname}:8080/v1/chat",
                authorized=False,
            )
            assert hostname in config.endpoint


# ─────────────────────────────────────────────────────────────────────────────
# Hardening fixes — targeted regression tests for each issue
# ─────────────────────────────────────────────────────────────────────────────

class TestHardeningFix1_NetlocWhitespace:
    """Issue 1: Whitespace anywhere in the URL authority must be rejected.

    The original implementation only checked parsed.hostname.  Whitespace in
    the userinfo component (before @) would pass that check because
    parsed.hostname strips the userinfo and returns only the bare host.
    """

    def test_whitespace_in_userinfo_rejected(self):
        """'user name@host' has whitespace in netloc but NOT in hostname."""
        assert raises_validation("https://user name@example.com/path")

    def test_whitespace_in_password_field_rejected(self):
        assert raises_validation("https://user:pass word@example.com")

    def test_valid_url_with_userinfo_no_space_still_accepted(self):
        """A userinfo component with no whitespace must not be rejected."""
        result = validate("https://user:pass@example.com/path")
        assert result == "https://user:pass@example.com/path"

    def test_hostname_whitespace_still_rejected(self):
        """Original hostname-whitespace check must remain in effect."""
        assert raises_validation("https://bad host.com/path")
        assert raises_validation("bad host.com")


class TestHardeningFix2_MalformedScheme:
    """Issue 2: 'http:example.com' (scheme without //) must be rejected with
    a clear, accurate error message — not silently reinterpreted as a
    scheme-less hostname.
    """

    def test_http_without_slashes_rejected(self):
        assert raises_validation("http:example.com")

    def test_https_without_slashes_rejected(self):
        assert raises_validation("https:example.com")

    def test_ftp_without_slashes_rejected(self):
        assert raises_validation("ftp:example.com")

    def test_ws_without_slashes_rejected(self):
        assert raises_validation("ws:example.com")

    def test_error_message_names_the_scheme(self):
        """The error message must name the malformed scheme, not a port."""
        with pytest.raises(TargetValidationError) as exc_info:
            TargetManager.validate_target_url("http:example.com")
        msg = str(exc_info.value)
        # Message must mention the apparent scheme, not 'Port must be numeric'
        assert "http" in msg
        assert "://" in msg
        assert "Port" not in msg

    def test_hostname_with_numeric_port_not_misidentified(self):
        """'localhost:8000' must NOT be treated as a malformed scheme."""
        result = validate("localhost:8000")
        assert result == "https://localhost:8000"

    def test_hostname_with_alpha_port_rejected_by_port_validator(self):
        """'example.com:abc' is a bad port, not a malformed scheme.
        It should raise TargetValidationError but with a port-related message.
        """
        with pytest.raises(TargetValidationError) as exc_info:
            TargetManager.validate_target_url("example.com:abc")
        msg = str(exc_info.value)
        assert "Port" in msg  # port-validation message, not scheme message

    def test_valid_http_url_unaffected(self):
        """'http://example.com' must still be accepted."""
        result = validate("http://example.com/path")
        assert result == "http://example.com/path"


class TestHardeningFix3_IPv6:
    """Issue 3: Valid bracketed IPv6 URLs must be accepted; malformed IPv6
    inputs must be rejected.
    """

    def test_ipv6_loopback_with_port_accepted(self):
        result = validate("https://[::1]:8080/path")
        assert result == "https://[::1]:8080/path"

    def test_ipv6_loopback_without_port_accepted(self):
        result = validate("https://[::1]/path")
        assert result == "https://[::1]/path"

    def test_schemeless_ipv6_defaults_to_https(self):
        result = validate("[::1]:8080/path")
        assert result == "https://[::1]:8080/path"

    def test_ipv6_full_address_with_port_accepted(self):
        result = validate("https://[2001:db8::1]:443/api")
        assert result == "https://[2001:db8::1]:443/api"

    def test_ipv6_loopback_auto_authorized(self):
        """[::1] is a loopback address and must be auto-authorized."""
        config = TargetManager.create_target_config(
            endpoint="https://[::1]:8080/chat",
            authorized=False,
        )
        assert config.endpoint == "https://[::1]:8080/chat"

    def test_malformed_ipv6_missing_close_bracket_rejected(self):
        """'https://[::1:8080/path' has no closing bracket."""
        assert raises_validation("https://[::1:8080/path")

    def test_malformed_ipv6_no_brackets_rejected(self):
        """'https://::1:8080/path' has colons but no brackets — not a valid host."""
        assert raises_validation("https://::1:8080/path")


class TestHardeningFix4_EmptyPortSuffix:
    """Issue 4: A trailing colon with no port number ('example.com:',
    'https://example.com:') must be rejected.

    urlparse.port returns None for both 'no port' and 'empty port suffix',
    making them indistinguishable without inspecting the raw netloc.
    """

    def test_https_empty_port_rejected(self):
        assert raises_validation("https://example.com:")

    def test_http_localhost_empty_port_rejected(self):
        assert raises_validation("http://localhost:")

    def test_schemeless_empty_port_rejected(self):
        assert raises_validation("example.com:")

    def test_localhost_empty_port_rejected(self):
        assert raises_validation("localhost:")

    def test_valid_port_still_accepted(self):
        """Ensure the fix does not regress valid port URLs."""
        assert validate("https://example.com:443/api") == "https://example.com:443/api"
        assert validate("http://localhost:8000") == "http://localhost:8000"

    def test_no_port_at_all_still_accepted(self):
        """A URL with no port at all must remain accepted."""
        assert validate("https://example.com/api") == "https://example.com/api"


class TestHardeningFix5_UnusedPortRE:
    """Issue 5: _PORT_RE was declared but never used.  It has been removed.
    Verify that port validation still works correctly through the urlparse
    path, and that no reference to _PORT_RE exists in the TargetManager class.
    """

    def test_port_re_not_present(self):
        assert not hasattr(TargetManager, "_PORT_RE"), (
            "_PORT_RE was dead code and should have been removed."
        )

    def test_port_validation_still_rejects_alpha_port(self):
        assert raises_validation("https://example.com:abc")

    def test_port_validation_still_rejects_zero(self):
        assert raises_validation("https://example.com:0")

    def test_port_validation_still_rejects_out_of_range(self):
        assert raises_validation("https://example.com:65536")

    def test_port_validation_still_accepts_valid_port(self):
        assert validate("https://example.com:8443") == "https://example.com:8443"
