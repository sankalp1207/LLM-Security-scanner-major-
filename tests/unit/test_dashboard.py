"""Unit tests for dashboard components and API client."""

from dashboard.api_client import ScannerAPIClient
from dashboard.components import severity_badge, status_badge


def test_severity_badge_html():
    """Verify severity badges generate valid HTML styling."""
    badge_crit = severity_badge("CRITICAL")
    assert "CRITICAL" in badge_crit
    assert "#fee2e2" in badge_crit

    badge_low = severity_badge("LOW")
    assert "LOW" in badge_low


def test_status_badge_html():
    """Verify status badges generate valid HTML styling."""
    badge_pass = status_badge("RETEST_PASSED")
    assert "RETEST_PASSED" in badge_pass

    badge_fail = status_badge("RETEST_FAILED")
    assert "RETEST_FAILED" in badge_fail


def test_dashboard_api_client_graceful_offline():
    """Verify API client handles unreachable backend without throwing unhandled exceptions."""
    client = ScannerAPIClient(base_url="http://127.0.0.1:9999")  # Non-existent port
    health = client.check_health()
    assert health["status"] == "unreachable"

    scans = client.list_scans()
    assert scans == []
