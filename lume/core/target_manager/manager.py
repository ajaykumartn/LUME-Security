"""Target validation, authorization checks, and configuration manager."""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from lume.adapters.base import TargetConfig


class TargetAuthorizationError(Exception):
    """Raised when target authorization is not explicitly granted or validated."""
    pass


class TargetValidationError(Exception):
    """Raised when target URL or configuration is invalid."""
    pass


class TargetManager:
    """Manages target configuration and enforces explicit authorization boundaries."""

    ALLOWED_SCHEMES: Tuple[str, ...] = ("http", "https")

    # Detects malformed scheme-like inputs such as "http:example.com" where
    # the user typed a recognised scheme token followed by a colon but without
    # the required "//".
    #
    # The pattern matches when:
    #   1. The string starts with an alpha-only scheme token (letters, digits,
    #      +, - but NOT a dot — dots distinguish hostnames like "example.com").
    #   2. Followed immediately by a colon.
    #   3. Followed by a non-slash, non-digit character.
    #
    # The third condition distinguishes "http:example.com" (char after colon is
    # a letter) from "localhost:8000" or "example.com:abc" (char after colon
    # is a digit in the valid-port case, and in the alpha-port case the port
    # validator will reject it later).
    _MALFORMED_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+\-]*:[^/0-9]")

    @classmethod
    def validate_target_url(cls, url: str) -> str:
        """Validate and normalise a target URL.

        Scheme-less inputs (bare hostnames, hostnames with ports or paths)
        are defaulted to HTTPS.  Explicit http:// and https:// inputs are
        preserved unchanged.  All other explicit schemes are rejected.

        Authority validation covers the full netloc string (including any
        user-information component), not only the hostname portion.

        Args:
            url: The target endpoint URL supplied by the user.

        Returns:
            Normalized URL string with a guaranteed http or https scheme.

        Raises:
            TargetValidationError: If the URL cannot be normalised safely.
        """
        # ── Type and emptiness check ───────────────────────────────────────
        if not isinstance(url, str):
            raise TargetValidationError("Target URL must be a non-empty string.")

        url = url.strip()

        if not url:
            raise TargetValidationError("Target URL must be a non-empty string.")

        # ── Issue 2: Malformed scheme-like inputs ("http:example.com") ─────
        # A colon immediately followed by a non-slash character means the
        # user typed a scheme without "//".  urlparse silently parses this
        # as a scheme + path (no netloc), which would then be prefixed with
        # "https://" and produce a nonsensical URL like
        # "https://http:example.com".  Catch and reject it explicitly.
        if cls._MALFORMED_SCHEME_RE.match(url):
            # Extract the token before the colon as the apparent scheme.
            apparent_scheme = url.split(":", 1)[0].lower()
            raise TargetValidationError(
                f"Malformed URL '{url}': scheme '{apparent_scheme}' must be followed by '://' "
                f"(e.g. https://example.com). "
                f"Only http:// and https:// are permitted."
            )

        # ── Scheme detection & normalisation ──────────────────────────────
        # urlparse treats "example.com/path" as path-only (no scheme, no
        # netloc), so we detect whether an explicit scheme was provided by
        # checking for "://" before attempting to parse.
        has_explicit_scheme = "://" in url

        if has_explicit_scheme:
            # User supplied a full URL — validate the scheme then hand off.
            explicit_scheme = url.split("://", 1)[0].lower()
            if explicit_scheme not in cls.ALLOWED_SCHEMES:
                raise TargetValidationError(
                    f"Unsupported URL scheme '{explicit_scheme}'. "
                    f"Only http:// and https:// are permitted."
                )
            normalised = url
        else:
            # No scheme supplied — default to HTTPS.
            normalised = "https://" + url

        # ── Structural parse ───────────────────────────────────────────────
        try:
            parsed = urlparse(normalised)
        except Exception:
            raise TargetValidationError(
                f"Target URL '{url}' could not be parsed. "
                f"Ensure it is a valid URL (e.g. https://example.com/api)."
            )

        # ── Issue 1: Full netloc / authority whitespace check ──────────────
        # parsed.hostname only covers the bare host; userinfo such as
        # "user name@host" passes the hostname check but must still be
        # rejected.  Validate the entire netloc string.
        if not parsed.netloc:
            raise TargetValidationError(
                f"Invalid target URL '{url}': Missing or empty host address."
            )

        if re.search(r"\s", parsed.netloc):
            raise TargetValidationError(
                f"Invalid target URL '{url}': URL authority must not contain whitespace."
            )

        # ── Hostname validation ────────────────────────────────────────────
        hostname = parsed.hostname  # None if parse failed or empty
        if not hostname:
            raise TargetValidationError(
                f"Invalid target URL '{url}': Missing or empty host address."
            )

        # ── Port validation ────────────────────────────────────────────────
        # urlparse.port raises ValueError for non-numeric ports; catch that.
        try:
            port = parsed.port  # None if absent; int if present
        except ValueError:
            raise TargetValidationError(
                f"Invalid target URL '{url}': Port must be a numeric value between 1 and 65535."
            )

        # Issue 4: Reject an empty port suffix such as "https://example.com:"
        # urlparse returns port=None for both "no port" and "empty port suffix",
        # so we must inspect the raw netloc to distinguish them.
        if parsed.netloc.endswith(":") or re.search(r":\s*$", parsed.netloc):
            raise TargetValidationError(
                f"Invalid target URL '{url}': Port must be a numeric value between 1 and 65535."
            )

        if port is not None and not (1 <= port <= 65535):
            raise TargetValidationError(
                f"Invalid target URL '{url}': Port {port} is out of the valid range (1-65535)."
            )

        return normalised

    @classmethod
    def verify_authorization(
        cls,
        target_url: str,
        authorized: bool = False,
    ) -> bool:
        """Verify that testing is authorized against the target.

        Args:
            target_url: Target URL to test.
            authorized: Flag confirming explicit user authorization.

        Returns:
            True if authorized.

        Raises:
            TargetAuthorizationError: If authorization is denied or missing.
        """
        # Localhost/loopback addresses in test environments are automatically permitted
        parsed = urlparse(target_url)
        is_loopback = parsed.hostname in (
            "localhost",
            "127.0.0.1",
            "::1",
            "test-ai",
            "vulnerable-ai",
            "protected-ai",
        )

        if is_loopback:
            return True

        if authorized:
            return True

        raise TargetAuthorizationError(
            f"Active security scanning against non-local target '{target_url}' requires explicit authorization. "
            f"Use the --authorized flag or provide explicit consent before scanning."
        )

    @classmethod
    def create_target_config(
        cls,
        endpoint: str,
        adapter_type: str = "http",
        timeout: float = 30.0,
        headers: Optional[dict] = None,
        model_name: Optional[str] = None,
        authorized: bool = False,
        proxy: Optional[str] = None,
        verify: bool = True,
        cert: Optional[str] = None,
        delay_ms: int = 0,
        user_agent: Optional[str] = None,
    ) -> TargetConfig:
        """Validate target and build a safe TargetConfig object."""
        normalized_url = cls.validate_target_url(endpoint)
        cls.verify_authorization(normalized_url, authorized=authorized)

        return TargetConfig(
            endpoint=normalized_url,
            adapter_type=adapter_type,
            timeout=timeout,
            headers=headers or {},
            model_name=model_name,
            proxy=proxy,
            verify=verify,
            cert=cert,
            delay_ms=delay_ms,
            user_agent=user_agent,
        )
