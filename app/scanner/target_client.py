"""Target client validating destination authorization and executing bounded HTTP requests."""

import ipaddress
import time
from urllib.parse import urlparse

import httpx

from app.scanner.base import ExecutionResult, TargetValidationResult


class TargetClient:
    """Manages secure communication with authorized LLM target endpoints."""

    # Prohibited destinations to prevent SSRF and infrastructure attacks
    PROHIBITED_HOSTS = {
        "169.254.169.254",  # AWS/GCP/Azure link-local cloud metadata
        "metadata.google.internal",
        "instance-data",
    }

    LOCAL_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0", "testserver"}

    @classmethod
    def validate_target(
        cls,
        target_url: str,
        external_authorized: bool = False,
    ) -> TargetValidationResult:
        """Validate destination URL against security policies."""
        if not target_url or not isinstance(target_url, str):
            return TargetValidationResult(
                is_valid=False, target_url=str(target_url), host="", is_local=False,
                error_message="Target URL cannot be empty."
            )

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return TargetValidationResult(
                is_valid=False, target_url=target_url, host="", is_local=False,
                error_message=f"Unsupported scheme '{parsed.scheme}'. Only http and https are permitted."
            )

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return TargetValidationResult(
                is_valid=False, target_url=target_url, host="", is_local=False,
                error_message="Invalid target URL: missing hostname."
            )

        # Cloud metadata protection
        if hostname in cls.PROHIBITED_HOSTS:
            return TargetValidationResult(
                is_valid=False, target_url=target_url, host=hostname, is_local=False,
                error_message="Requests to cloud metadata endpoints are strictly prohibited."
            )

        is_local = hostname in cls.LOCAL_HOSTS

        # Check if IP address is link-local or multicast
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return TargetValidationResult(
                    is_valid=False, target_url=target_url, host=hostname, is_local=False,
                    error_message="Requests to reserved or link-local IP addresses are prohibited."
                )
            if ip.is_loopback:
                is_local = True
        except ValueError:
            # Not a raw IP address; hostname string
            pass

        # If non-local target, require explicit authorization acknowledgement
        if not is_local and not external_authorized:
            return TargetValidationResult(
                is_valid=False, target_url=target_url, host=hostname, is_local=False,
                error_message=(
                    "External target requires explicit authorization acknowledgement. "
                    "Set external_target_authorized=True in scan configuration."
                )
            )

        return TargetValidationResult(
            is_valid=True,
            target_url=target_url,
            host=hostname,
            is_local=is_local,
            error_message=None,
        )

    @classmethod
    async def execute_test(
        cls,
        target_url: str,
        test_case_id: str,
        category: str,
        input_text: str,
        timeout_seconds: float = 10.0,
        client: httpx.AsyncClient | None = None,
        metadata: dict | None = None,
    ) -> ExecutionResult:
        """Send asynchronous test request to target and capture telemetry."""
        payload = {"query": input_text}
        start_time = time.perf_counter()

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False)
            should_close = True

        try:
            req_call = client.post(
                target_url,
                json=payload,
                headers={"User-Agent": "LLM-Security-Scanner/1.0", "Content-Type": "application/json"},
            )
            import inspect
            if inspect.isawaitable(req_call):
                response = await req_call
            else:
                response = req_call
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Parse response payload
            response_text = ""
            retrieved_docs = []
            try:
                data = response.json()
                if isinstance(data, dict):
                    response_text = str(data.get("response", data.get("text", data.get("answer", ""))))
                    retrieved_docs = data.get("retrieved_documents", [])
                else:
                    response_text = str(data)
            except Exception:
                response_text = response.text[:4096]

            return ExecutionResult(
                test_case_id=test_case_id,
                category=category,
                input_text=input_text,
                response_status=response.status_code,
                response_text=response_text,
                retrieved_documents=retrieved_docs,
                latency_ms=round(elapsed_ms, 2),
                error=None,
                is_inconclusive=response.status_code >= 500,
                metadata=metadata or {},
            )
        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                test_case_id=test_case_id,
                category=category,
                input_text=input_text,
                response_status=None,
                latency_ms=round(elapsed_ms, 2),
                error=f"Request timed out after {timeout_seconds}s",
                is_inconclusive=True,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                test_case_id=test_case_id,
                category=category,
                input_text=input_text,
                response_status=None,
                latency_ms=round(elapsed_ms, 2),
                error=f"Connection error: {str(e)}",
                is_inconclusive=True,
            )
        finally:
            if should_close and hasattr(client, "aclose"):
                await client.aclose()
