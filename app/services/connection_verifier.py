"""Connection verification service with enterprise SSRF protections and provider diagnostics."""

import ipaddress
import socket
import time
from urllib.parse import urlparse
from typing import Any, Dict, Optional, Tuple

import httpx

from app.schemas.projects import ConnectionVerificationResponse


class ConnectionVerifier:
    """Safely validates target accessibility, authentication, and compatibility without adversarial payloads."""

    # Prohibited metadata and internal infrastructure hosts
    PROHIBITED_METADATA_HOSTS = {
        "169.254.169.254",
        "metadata.google.internal",
        "instance-data",
        "100.100.100.200",  # Alibaba cloud metadata
    }

    LOCAL_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0", "testserver"}

    @classmethod
    def validate_destination_ssrf(
        cls,
        url: str,
        allow_local: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """
        Enforce strict SSRF filtering on target URL.
        Returns (is_allowed, error_reason).
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Malformed target URL."

        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are permitted."

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            return False, "Target URL missing valid hostname."

        # Check cloud metadata prohibited destinations
        if hostname in cls.PROHIBITED_METADATA_HOSTS:
            return False, "Requests to cloud metadata endpoints are strictly blocked by SSRF policy."

        # Check if hostname is local
        is_local_host = hostname in cls.LOCAL_HOSTS
        if is_local_host and not allow_local:
            return False, f"Destination host '{hostname}' is a local loopback interface and not permitted for external target types."
        if is_local_host and allow_local:
            return True, None

        # Attempt DNS resolution and IP address range check
        try:
            # Check if hostname is directly an IP literal
            ip_obj = ipaddress.ip_address(hostname)
            ip_list = [ip_obj]
        except ValueError:
            # Resolve DNS
            try:
                addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                ip_list = [ipaddress.ip_address(item[4][0]) for item in addr_info]
            except Exception as e:
                return False, f"Could not resolve hostname '{hostname}': {str(e)}"

        for ip in ip_list:
            if ip.is_loopback:
                if not allow_local:
                    return False, f"Target resolves to loopback IP {ip}. Prohibited for external targets."
            elif ip.is_private:
                if not allow_local:
                    return False, f"Target resolves to private network IP {ip}. Prohibited for external targets."
            elif ip.is_link_local:
                return False, f"Target resolves to link-local IP {ip}. Prohibited."
            elif ip.is_multicast or ip.is_reserved:
                return False, f"Target resolves to reserved or multicast IP {ip}. Prohibited."

        return True, None

    @classmethod
    async def verify_connection(
        cls,
        endpoint_url: str,
        target_type: str = "demo",
        provider: str = "demo",
        auth_type: str = "none",
        credential: Optional[str] = None,
        timeout_seconds: float = 10.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> ConnectionVerificationResponse:
        """
        Perform a safe, bounded diagnostic probe against the specified target.
        """
        # 1. Determine local policy based on target type
        allow_local = target_type in ("demo", "local_llm")

        # 2. SSRF Destination Validation
        is_safe, error_reason = cls.validate_destination_ssrf(endpoint_url, allow_local=allow_local)
        if not is_safe:
            return ConnectionVerificationResponse(
                is_connected=False,
                status="BLOCKED",
                status_code=None,
                latency_ms=None,
                message=f"Connection blocked by security policy: {error_reason}",
                remediation="Ensure the endpoint URL is publicly routable and does not target internal or cloud metadata infrastructure.",
                tested_url=endpoint_url,
                details={"security_violation": "SSRF_PREVENTION", "reason": error_reason},
            )

        # 3. Handle built-in Demo Target
        if target_type == "demo" or "demo-rag" in endpoint_url:
            parsed = urlparse(endpoint_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            is_local = (parsed.hostname or "").lower() in cls.LOCAL_HOSTS or "demo-rag" in endpoint_url
            probe_url = f"{base_url}/health" if is_local else endpoint_url

            start_t = time.perf_counter()
            try:
                if http_client is not None:
                    res = await http_client.get(probe_url, timeout=timeout_seconds)
                elif is_local:
                    from app.main import app
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                        res = await client.get("/health", timeout=timeout_seconds)
                else:
                    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
                        res = await client.get(probe_url)

                elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
                if res.status_code in (200, 204):
                    return ConnectionVerificationResponse(
                        is_connected=True,
                        status="CONNECTED",
                        status_code=res.status_code,
                        latency_ms=elapsed_ms,
                        message="Local demo environment operational and responsive.",
                        remediation="Target is ready for security scanning and red-team evaluation.",
                        tested_url=probe_url,
                        details={"provider": "demo", "response_bytes": len(res.content)},
                    )
                else:
                    return ConnectionVerificationResponse(
                        is_connected=False,
                        status="UNAVAILABLE",
                        status_code=res.status_code,
                        latency_ms=elapsed_ms,
                        message=f"Target returned non-success status code {res.status_code}.",
                        remediation="Verify that the local FastAPI server is running with 'uvicorn app.main:app'.",
                        tested_url=probe_url,
                    )
            except Exception as exc:
                return ConnectionVerificationResponse(
                    is_connected=False,
                    status="UNAVAILABLE",
                    status_code=None,
                    latency_ms=None,
                    message=f"Connection failed: {str(exc)}",
                    remediation="Start the local API backend: 'uvicorn app.main:app --reload'.",
                    tested_url=probe_url,
                )

        # 4. Handle External or Local LLM targets
        headers: Dict[str, str] = {
            "User-Agent": "LLM-Security-Scanner/1.0 (ConnectionVerifier)",
            "Accept": "application/json",
        }
        if auth_type == "bearer" and credential:
            headers["Authorization"] = f"Bearer {credential}"
        elif auth_type == "api_key" and credential:
            headers["x-api-key"] = credential

        start_t = time.perf_counter()
        try:
            # Safe non-adversarial GET or HEAD probe
            client_to_use = http_client or httpx.AsyncClient(
                timeout=timeout_seconds,
                follow_redirects=False,
                limits=httpx.Limits(max_keepalive_connections=2, max_connections=2),
            )
            async with client_to_use as client:
                try:
                    res = await client.get(endpoint_url, headers=headers)
                except httpx.HTTPStatusError:
                    res = await client.post(endpoint_url, headers=headers, json={"query": "healthcheck"})

            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)

            # Check HTTP Status Codes
            if res.status_code in (200, 201, 204):
                return ConnectionVerificationResponse(
                    is_connected=True,
                    status="CONNECTED",
                    status_code=res.status_code,
                    latency_ms=elapsed_ms,
                    message=f"Successfully connected to target ({res.status_code} OK).",
                    remediation="Target is reachable. You may now launch security audits.",
                    tested_url=endpoint_url,
                    details={"latency_ms": elapsed_ms, "headers_count": len(res.headers)},
                )
            elif res.status_code in (401, 403):
                return ConnectionVerificationResponse(
                    is_connected=False,
                    status="AUTH_FAILED",
                    status_code=res.status_code,
                    latency_ms=elapsed_ms,
                    message=f"Target rejected credentials with status {res.status_code}.",
                    remediation="Check the API Key or Bearer token configuration in Target Configuration.",
                    tested_url=endpoint_url,
                )
            elif res.status_code in (404, 405):
                # Endpoint reachable but path or method differs
                return ConnectionVerificationResponse(
                    is_connected=True,
                    status="CONNECTED",
                    status_code=res.status_code,
                    latency_ms=elapsed_ms,
                    message=f"Target host reachable (HTTP {res.status_code} returned).",
                    remediation="Verify the exact endpoint URL path (e.g. /v1/chat/completions or /api/query).",
                    tested_url=endpoint_url,
                )
            elif res.status_code >= 500:
                return ConnectionVerificationResponse(
                    is_connected=False,
                    status="UNAVAILABLE",
                    status_code=res.status_code,
                    latency_ms=elapsed_ms,
                    message=f"Target application returned server error HTTP {res.status_code}.",
                    remediation="Check remote application logs or health status.",
                    tested_url=endpoint_url,
                )
            else:
                return ConnectionVerificationResponse(
                    is_connected=False,
                    status="INVALID_RESPONSE",
                    status_code=res.status_code,
                    latency_ms=elapsed_ms,
                    message=f"Target returned unexpected HTTP {res.status_code}.",
                    remediation="Confirm the target accepts standard HTTP JSON requests.",
                    tested_url=endpoint_url,
                )

        except httpx.TimeoutException:
            return ConnectionVerificationResponse(
                is_connected=False,
                status="TIMEOUT",
                status_code=None,
                latency_ms=None,
                message=f"Connection timed out after {timeout_seconds} seconds.",
                remediation="Check network latency, target firewall rules, or increase connection timeout.",
                tested_url=endpoint_url,
            )
        except httpx.ConnectError as ce:
            return ConnectionVerificationResponse(
                is_connected=False,
                status="UNAVAILABLE",
                status_code=None,
                latency_ms=None,
                message=f"Could not connect to target host: {str(ce)}",
                remediation="Verify target host is active, DNS is correct, and port is open.",
                tested_url=endpoint_url,
            )
        except Exception as e:
            return ConnectionVerificationResponse(
                is_connected=False,
                status="UNAVAILABLE",
                status_code=None,
                latency_ms=None,
                message=f"Connection test error: {str(e)}",
                remediation="Inspect endpoint configuration and retry.",
                tested_url=endpoint_url,
            )

