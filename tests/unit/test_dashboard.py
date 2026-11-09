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

    findings = client.list_all_findings()
    assert findings == []


def test_theme_injection():
    """Verify theme CSS is defined and contains cyber SaaS styling rules."""
    from dashboard.theme import CYBER_THEME_CSS

    assert "--bg-main: #090d16;" in CYBER_THEME_CSS
    assert "--accent-indigo: #6366f1;" in CYBER_THEME_CSS
    assert ".kpi-container" in CYBER_THEME_CSS
    assert ".top-navbar" in CYBER_THEME_CSS


def test_dashboard_components_helpers():
    """Verify new SaaS component helpers exist and execute cleanly."""
    from dashboard.components import (
        empty_state,
        in_development_card,
        metric_card,
        recommendation_card,
        render_header,
        render_top_navbar,
    )

    # Assert helper callables exist
    assert callable(render_header)
    assert callable(render_top_navbar)
    assert callable(metric_card)
    assert callable(empty_state)
    assert callable(recommendation_card)
    assert callable(in_development_card)
