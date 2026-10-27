"""Unit tests for Target Adapters and Target Manager."""

import pytest

from lume.adapters.local.mock import LocalMockAdapter
from lume.core.target_manager.manager import (
    TargetAuthorizationError,
    TargetManager,
    TargetValidationError,
)


def test_target_manager_url_validation():
    # Valid URLs with explicit scheme — returned unchanged
    assert TargetManager.validate_target_url("http://localhost:8000") == "http://localhost:8000"
    assert TargetManager.validate_target_url("https://api.example.com/v1") == "https://api.example.com/v1"

    # Scheme-less input is now normalised to HTTPS instead of rejected
    assert TargetManager.validate_target_url("localhost:8000") == "https://localhost:8000"

    # Unsupported scheme
    with pytest.raises(TargetValidationError):
        TargetManager.validate_target_url("ftp://localhost:8000")

    # Empty URL
    with pytest.raises(TargetValidationError):
        TargetManager.validate_target_url("")


def test_target_manager_authorization():
    # Localhost is auto-authorized
    assert TargetManager.verify_authorization("http://localhost:8000") is True
    assert TargetManager.verify_authorization("http://127.0.0.1:8080") is True

    # External targets require explicit confirmation
    with pytest.raises(TargetAuthorizationError):
        TargetManager.verify_authorization("https://external-target.com", authorized=False)

    assert TargetManager.verify_authorization("https://external-target.com", authorized=True) is True


def test_local_mock_adapter():
    adapter = LocalMockAdapter(response_handler=lambda p: f"Echo: {p}")
    assert adapter.adapter_type == "local"
    assert adapter.health_check() is True

    resp = adapter.send_prompt("Hello LUME")
    assert resp.raw_text == "Echo: Hello LUME"
    assert resp.status_code == 200


def test_http_adapter_payload_and_headers():
    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://api.openai-client.com/v1/chat/completions",
        headers={"Authorization": "Bearer test-key-123", "X-Client-Org": "Org-42"},
        model_name="gpt-4o",
        extra_params={"payload_format": "openai"},
    )
    adapter = HTTPTargetAdapter(config)
    assert adapter.default_headers["Authorization"] == "Bearer test-key-123"
    assert adapter.default_headers["X-Client-Org"] == "Org-42"
    assert adapter.default_headers["User-Agent"] == "LUME-Security-Scanner/0.1.0"

    body = adapter._build_request_body("test injection prompt")
    assert body["model"] == "gpt-4o"
    assert "messages" in body
    assert body["messages"][0]["role"] == "user"
    assert body["messages"][0]["content"] == "test injection prompt"


def test_target_manager_create_target_config_pentest_options():
    cfg = TargetManager.create_target_config(
        endpoint="http://localhost:8000/api",
        proxy="http://127.0.0.1:8080",
        verify=False,
        delay_ms=150,
        user_agent="Kali-Pentest-Agent/1.0",
        authorized=True,
    )
    assert cfg.proxy == "http://127.0.0.1:8080"
    assert cfg.verify is False
    assert cfg.delay_ms == 150
    assert cfg.user_agent == "Kali-Pentest-Agent/1.0"


def test_http_adapter_custom_user_agent():
    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    # Config user_agent
    config = TargetConfig(
        endpoint="http://localhost:8000/api",
        user_agent="BurpSuitePentest/2.0",
    )
    adapter = HTTPTargetAdapter(config)
    assert adapter.user_agent == "BurpSuitePentest/2.0"
    assert adapter.default_headers["User-Agent"] == "BurpSuitePentest/2.0"

    # Adapter init user_agent override
    adapter_override = HTTPTargetAdapter(config, user_agent="OWASP-ZAP/2.14")
    assert adapter_override.user_agent == "OWASP-ZAP/2.14"
    assert adapter_override.default_headers["User-Agent"] == "OWASP-ZAP/2.14"


@pytest.mark.asyncio
async def test_http_adapter_async_client_proxy_and_verify():
    from unittest.mock import AsyncMock, MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://target.internal/api/chat",
        proxy="http://127.0.0.1:8080",
        verify=False,
        user_agent="BurpSuitePentest/2.0",
    )
    adapter = HTTPTargetAdapter(config)
    assert adapter.proxy == "http://127.0.0.1:8080"
    assert adapter.verify is False

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {"response": "Pwned"}

    mock_client_instance = AsyncMock()
    mock_client_instance.post.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        resp = await adapter.send_prompt_async("Test prompt")

        mock_async_client.assert_called_once_with(
            timeout=30.0,
            verify=False,
            proxy="http://127.0.0.1:8080",
        )
        assert resp.raw_text == "Pwned"
        assert resp.status_code == 200


def test_http_adapter_sync_client_proxy_and_verify():
    from unittest.mock import MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://target.internal/api/chat",
        proxy="http://127.0.0.1:8080",
        verify=False,
        user_agent="ZapPentest/1.0",
    )
    adapter = HTTPTargetAdapter(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {"reply": "Echo"}

    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp

    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value = mock_client_instance
        resp = adapter.send_prompt("Test prompt")

        mock_client.assert_called_once_with(
            timeout=30.0,
            verify=False,
            proxy="http://127.0.0.1:8080",
        )
        assert resp.raw_text == "Echo"


def test_http_adapter_health_check_with_proxy_and_insecure():
    from unittest.mock import MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://staging.internal:8443/health",
        proxy="http://127.0.0.1:8080",
        verify=False,
        user_agent="BurpSuite/1.0",
    )
    adapter = HTTPTargetAdapter(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_resp

    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value = mock_client_instance
        is_healthy = adapter.health_check()

        assert is_healthy is True
        mock_client.assert_called_once_with(
            timeout=5.0,
            verify=False,
            proxy="http://127.0.0.1:8080",
        )
        mock_client_instance.get.assert_called_once_with(
            "https://staging.internal:8443/health",
            headers=adapter.default_headers,
        )


@pytest.mark.asyncio
async def test_http_adapter_delay_async():
    from unittest.mock import AsyncMock, MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://target.internal/api/chat",
        delay_ms=250,
    )
    adapter = HTTPTargetAdapter(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "OK"}
    mock_client_instance = AsyncMock()
    mock_client_instance.post.return_value = mock_resp

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep, \
         patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value = mock_client_instance

        await adapter.send_prompt_async("Prompt 1")
        mock_sleep.assert_called_once_with(0.25)

        # Explicit per-call delay_ms override
        mock_sleep.reset_mock()
        await adapter.send_prompt_async("Prompt 2", delay_ms=500)
        mock_sleep.assert_called_once_with(0.5)

        # 0 delay should not call sleep
        mock_sleep.reset_mock()
        await adapter.send_prompt_async("Prompt 3", delay_ms=0)
        mock_sleep.assert_not_called()


def test_http_adapter_delay_sync():
    from unittest.mock import MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://target.internal/api/chat",
        delay_ms=100,
    )
    adapter = HTTPTargetAdapter(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "OK"}
    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp

    with patch("time.sleep") as mock_sleep, \
         patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value = mock_client_instance

        adapter.send_prompt("Prompt 1")
        mock_sleep.assert_called_once_with(0.1)


@pytest.mark.asyncio
async def test_test_executor_with_delay():
    from unittest.mock import AsyncMock

    from lume.adapters.base import TargetConfig, TargetResponse
    from lume.adapters.local.mock import LocalMockAdapter
    from lume.core.executor.base import TestExecutor

    cfg = TargetConfig(endpoint="local://mock", delay_ms=75)
    adapter = LocalMockAdapter(cfg)
    adapter.send_prompt_async = AsyncMock(return_value=TargetResponse(raw_text="Echo", status_code=200))

    executor = TestExecutor(adapter)
    assert executor.delay_ms == 75

    res = await executor.execute_prompt_async(test_id="T1", prompt="Hello")
    assert res.success is True
    adapter.send_prompt_async.assert_called_once_with("Hello", delay_ms=75)


def test_http_adapter_cert_from_config():
    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://staging.internal:8443/api",
        cert="/etc/lume/client.pem",
        verify=False,
    )
    adapter = HTTPTargetAdapter(config)
    assert adapter.cert == "/etc/lume/client.pem"

    # Verify _get_client_kwargs includes cert
    kwargs = adapter._get_client_kwargs(timeout=10.0)
    assert kwargs["cert"] == "/etc/lume/client.pem"
    assert kwargs["verify"] is False


def test_http_adapter_cert_override_at_init():
    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://staging.internal:8443/api",
        cert="/etc/lume/original.pem",
    )
    adapter = HTTPTargetAdapter(config, cert="/tmp/override.pem")
    assert adapter.cert == "/tmp/override.pem"

    kwargs = adapter._get_client_kwargs(timeout=5.0)
    assert kwargs["cert"] == "/tmp/override.pem"


def test_http_adapter_no_cert_omits_key():
    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(endpoint="http://localhost:8000/api")
    adapter = HTTPTargetAdapter(config)
    assert adapter.cert is None

    kwargs = adapter._get_client_kwargs(timeout=5.0)
    assert "cert" not in kwargs


def test_http_adapter_cert_passed_to_httpx_sync():
    from unittest.mock import MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://target.internal/api",
        cert="/etc/lume/client.pem",
        verify=False,
    )
    adapter = HTTPTargetAdapter(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {"response": "OK"}
    mock_client_instance = MagicMock()
    mock_client_instance.post.return_value = mock_resp

    with patch("httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value = mock_client_instance
        adapter.send_prompt("test")

        mock_client.assert_called_once_with(
            timeout=30.0,
            verify=False,
            cert="/etc/lume/client.pem",
        )


@pytest.mark.asyncio
async def test_http_adapter_cert_passed_to_httpx_async():
    from unittest.mock import AsyncMock, MagicMock, patch

    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://target.internal/api",
        cert="/etc/lume/client.pem",
        verify=False,
    )
    adapter = HTTPTargetAdapter(config)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {"response": "OK"}
    mock_client_instance = AsyncMock()
    mock_client_instance.post.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance
        resp = await adapter.send_prompt_async("test")

        mock_async_client.assert_called_once_with(
            timeout=30.0,
            verify=False,
            cert="/etc/lume/client.pem",
        )
        assert resp.status_code == 200


def test_target_manager_create_config_with_cert():
    cfg = TargetManager.create_target_config(
        endpoint="http://localhost:8000/api",
        cert="/etc/lume/client.pem",
        authorized=True,
    )
    assert cfg.cert == "/etc/lume/client.pem"
