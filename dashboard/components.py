"""UI components, metrics cards, and badge styling for Streamlit dashboard."""

from typing import Any, Dict, List, Optional
import streamlit as st


def render_header(title: str, subtitle: str, badge: Optional[str] = None) -> None:
    """Render standardized dashboard page header with modern SaaS styling."""
    badge_html = f'<span class="navbar-badge" style="margin-left: 10px;">{badge}</span>' if badge else ""
    st.markdown(
        f"""
        <div style="margin-bottom: 24px;">
            <div style="display: flex; align-items: center;">
                <h1 style="margin: 0; font-weight: 700; font-size: 1.85rem; color: #f8fafc; letter-spacing: -0.02em;">
                    {title}
                </h1>
                {badge_html}
            </div>
            <p style="color: #94a3b8; font-size: 0.95rem; margin-top: 6px; margin-bottom: 0px; line-height: 1.5;">
                {subtitle}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_top_navbar(
    current_project: str = "ACME Enterprise RAG",
    backend_status: str = "Online",
    version: str = "v1.0.0",
) -> None:
    """Render enterprise SaaS top bar with project switcher and status indicator."""
    status_color = "#10b981" if backend_status.lower() == "online" else "#ef4444"
    status_bg = "rgba(16, 185, 129, 0.15)" if backend_status.lower() == "online" else "rgba(239, 68, 68, 0.15)"

    st.markdown(
        f"""
        <div class="top-navbar">
            <div class="navbar-brand">
                <span style="font-size: 1.4rem;">🛡️</span>
                <div>
                    <div class="navbar-title">LLM Security Operations Center</div>
                    <div style="font-size: 0.75rem; color: #64748b;">Enterprise Continuous AI Threat Auditing</div>
                </div>
            </div>
            <div class="navbar-controls">
                <div style="display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); padding: 5px 12px; border-radius: 8px; font-size: 0.8rem; color: #cbd5e1;">
                    <span style="color: #8b5cf6;">📁</span>
                    <span>Project: <strong>{current_project}</strong></span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px; background: {status_bg}; border: 1px solid {status_color}44; padding: 5px 12px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; color: {status_color};">
                    <span style="width: 7px; height: 7px; border-radius: 50%; background-color: {status_color}; display: inline-block;"></span>
                    <span>{backend_status} ({version})</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(
    title: str,
    value: Any,
    subtitle: str,
    icon: str = "📊",
    trend: Optional[str] = None,
    trend_type: str = "neutral",
) -> None:
    """Render a premium SaaS KPI metric card with trends and icons."""
    trend_class = "trend-pos" if trend_type == "pos" else ("trend-neg" if trend_type == "neg" else "trend-neutral")
    trend_html = f'<div class="kpi-trend {trend_class}">{trend}</div>' if trend else ""

    st.markdown(
        f"""
        <div class="kpi-container">
            <div class="kpi-top-row">
                <span class="kpi-label">{title}</span>
                <div class="kpi-icon-pill">{icon}</div>
            </div>
            <div class="kpi-value">{value}</div>
            <div style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 6px;">{subtitle}</div>
            {trend_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    """Return colored HTML badge for a vulnerability severity."""
    sev = str(severity).upper()
    colors = {
        "CRITICAL": {"bg": "#fee2e2", "text": "#991b1b", "border": "#ef4444", "pill": "pill-critical"},
        "HIGH": {"bg": "#ffedd5", "text": "#9a3412", "border": "#f97316", "pill": "pill-high"},
        "MEDIUM": {"bg": "#fef9c3", "text": "#854d0e", "border": "#eab308", "pill": "pill-medium"},
        "LOW": {"bg": "#e0f2fe", "text": "#075985", "border": "#38bdf8", "pill": "pill-low"},
        "INFORMATIONAL": {"bg": "#f1f5f9", "text": "#475569", "border": "#94a3b8", "pill": "pill-info"},
    }
    style = colors.get(sev, {"bg": "#f1f5f9", "text": "#475569", "border": "#94a3b8", "pill": "pill-info"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style["border"]}; padding: 3px 10px; border-radius: 9999px; '
        f'font-weight: 600; font-size: 0.78rem; text-transform: uppercase;">{sev}</span>'
    )


def status_badge(status: str) -> str:
    """Return colored HTML badge for execution status."""
    st_val = str(status).upper()
    colors = {
        "COMPLETED": {"bg": "#dcfce7", "text": "#166534", "border": "#10b981"},
        "RUNNING": {"bg": "#dbeafe", "text": "#1e40af", "border": "#3b82f6"},
        "FAILED": {"bg": "#fee2e2", "text": "#991b1b", "border": "#ef4444"},
        "PARTIALLY_COMPLETED": {"bg": "#fef3c7", "text": "#92400e", "border": "#f59e0b"},
        "RETEST_PASSED": {"bg": "#dcfce7", "text": "#166534", "border": "#10b981"},
        "RETEST_FAILED": {"bg": "#fee2e2", "text": "#991b1b", "border": "#ef4444"},
        "NOT_RETESTED": {"bg": "#f1f5f9", "text": "#475569", "border": "#64748b"},
    }
    style = colors.get(st_val, {"bg": "#f1f5f9", "text": "#475569", "border": "#64748b"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style.get("border", "transparent")}; padding: 3px 9px; '
        f'border-radius: 6px; font-weight: 600; font-size: 0.78rem;">{st_val}</span>'
    )


def empty_state(title: str, description: str, icon: str = "🔍") -> None:
    """Render modern empty state placeholder."""
    st.markdown(
        f"""
        <div class="empty-box">
            <div class="empty-icon">{icon}</div>
            <div class="empty-title">{title}</div>
            <div class="empty-subtitle">{description}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def recommendation_card(
    title: str,
    severity: str,
    category: str,
    description: str,
    remediation: str,
) -> None:
    """Render an evidence-based security recommendation card."""
    st.markdown(
        f"""
        <div class="rec-item">
            <div class="rec-title">
                <span>{title}</span>
                <div>{severity_badge(severity)}</div>
            </div>
            <div style="font-size: 0.78rem; color: #8b5cf6; margin-bottom: 6px; font-weight: 600;">
                Category: <code>{category}</code>
            </div>
            <div class="rec-desc">{description}</div>
            <div style="margin-top: 8px; font-size: 0.8rem; color: #cbd5e1; background: rgba(0,0,0,0.25); padding: 8px 10px; border-radius: 6px;">
                💡 <strong>Remediation:</strong> {remediation}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def in_development_card(
    feature_name: str,
    roadmap_details: str,
    phase: str = "Phase 2 / Phase 3",
) -> None:
    """Render an informative development state for upcoming architecture modules."""
    st.markdown(
        f"""
        <div class="sec-card" style="border-left: 4px solid #8b5cf6; margin-top: 10px;">
            <div class="sec-card-header">
                <div class="sec-card-title">
                    <span>🚧</span>
                    <span>{feature_name}</span>
                </div>
                <span class="navbar-badge">{phase}</span>
            </div>
            <p style="color: #94a3b8; font-size: 0.92rem; line-height: 1.6; margin-bottom: 14px;">
                {roadmap_details}
            </p>
            <div style="display: flex; gap: 10px; align-items: center; font-size: 0.82rem; color: #64748b;">
                <span>⚡ Backend Architecture Defined</span>
                <span>•</span>
                <span>🔒 Security Model Specified</span>
                <span>•</span>
                <span>📋 Ready for Next Phase Implementation</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_stepper(
    current_step: int,
    total_steps: int = 6,
    step_labels: Optional[List[str]] = None,
) -> None:
    """Render a visual step-by-step progress indicator for onboarding."""
    labels = step_labels or [
        "1. Project Scope",
        "2. Target Type",
        "3. Target Config",
        "4. Preferences",
        "5. Verification",
        "6. Complete",
    ]

    steps_html = []
    for i, label in enumerate(labels, 1):
        if i < current_step:
            circle = '<span style="background: #10b981; color: white; border-radius: 50%; width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: bold;">✓</span>'
            color = "#10b981"
            weight = "600"
        elif i == current_step:
            circle = f'<span style="background: #6366f1; color: white; border-radius: 50%; width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: bold; box-shadow: 0 0 10px rgba(99,102,241,0.6);">{i}</span>'
            color = "#ffffff"
            weight = "700"
        else:
            circle = f'<span style="background: rgba(255,255,255,0.06); color: #64748b; border: 1px solid rgba(255,255,255,0.1); border-radius: 50%; width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem;">{i}</span>'
            color = "#64748b"
            weight = "400"

        steps_html.append(
            f'<div style="display: flex; align-items: center; gap: 6px; color: {color}; font-size: 0.8rem; font-weight: {weight};">'
            f'{circle} <span>{label}</span>'
            f'</div>'
        )

    stepper_body = ' <span style="color: rgba(255,255,255,0.15); margin: 0 4px;">─►</span> '.join(steps_html)

    st.markdown(
        f"""
        <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 12px 18px; margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between; overflow-x: auto;">
            {stepper_body}
        </div>
        """,
        unsafe_allow_html=True,
    )


def connection_status_badge(status: str) -> str:
    """Return colored HTML badge for target connection status."""
    st_val = str(status).upper()
    colors = {
        "CONNECTED": {"bg": "rgba(16, 185, 129, 0.15)", "text": "#6ee7b7", "border": "#10b981"},
        "AUTH_FAILED": {"bg": "rgba(239, 68, 68, 0.15)", "text": "#fca5a5", "border": "#ef4444"},
        "UNAVAILABLE": {"bg": "rgba(245, 158, 11, 0.15)", "text": "#fcd34d", "border": "#f59e0b"},
        "TIMEOUT": {"bg": "rgba(249, 115, 22, 0.15)", "text": "#fdba74", "border": "#f97316"},
        "BLOCKED": {"bg": "rgba(239, 68, 68, 0.2)", "text": "#f87171", "border": "#dc2626"},
        "UNVERIFIED": {"bg": "rgba(100, 116, 139, 0.15)", "text": "#cbd5e1", "border": "#64748b"},
    }
    style = colors.get(st_val, {"bg": "rgba(100, 116, 139, 0.15)", "text": "#cbd5e1", "border": "#64748b"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style["border"]}; padding: 3px 10px; border-radius: 9999px; '
        f'font-weight: 600; font-size: 0.75rem; text-transform: uppercase;">{st_val}</span>'
    )


def scan_preset_badge(preset_id: str) -> str:
    """Return colored HTML badge for scan presets."""
    p_val = str(preset_id).lower()
    presets = {
        "quick_scan": {"label": "QUICK SCAN", "bg": "rgba(59, 130, 246, 0.15)", "text": "#93c5fd", "border": "#3b82f6"},
        "full_scan": {"label": "FULL SCAN", "bg": "rgba(139, 92, 246, 0.15)", "text": "#c4b5fd", "border": "#8b5cf6"},
        "deep_red_team": {"label": "DEEP RED TEAM", "bg": "rgba(239, 68, 68, 0.15)", "text": "#fca5a5", "border": "#ef4444"},
    }
    style = presets.get(p_val, {"label": p_val.replace("_", " ").upper(), "bg": "rgba(100, 116, 139, 0.15)", "text": "#cbd5e1", "border": "#64748b"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style["border"]}; padding: 3px 10px; border-radius: 9999px; '
        f'font-weight: 700; font-size: 0.75rem; letter-spacing: 0.05em;">{style["label"]}</span>'
    )


def test_outcome_badge(status: str) -> str:
    """Return colored HTML badge for test execution outcome."""
    st_val = str(status).upper()
    colors = {
        "PASSED": {"bg": "rgba(16, 185, 129, 0.15)", "text": "#6ee7b7", "border": "#10b981"},
        "FAILED": {"bg": "rgba(239, 68, 68, 0.15)", "text": "#fca5a5", "border": "#ef4444"},
        "INCONCLUSIVE": {"bg": "rgba(245, 158, 11, 0.15)", "text": "#fcd34d", "border": "#f59e0b"},
        "SKIPPED": {"bg": "rgba(100, 116, 139, 0.15)", "text": "#cbd5e1", "border": "#64748b"},
        "ERROR": {"bg": "rgba(239, 68, 68, 0.2)", "text": "#f87171", "border": "#dc2626"},
    }
    style = colors.get(st_val, {"bg": "rgba(100, 116, 139, 0.15)", "text": "#cbd5e1", "border": "#64748b"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style["border"]}; padding: 2px 8px; border-radius: 6px; '
        f'font-weight: 600; font-size: 0.72rem; text-transform: uppercase;">{st_val}</span>'
    )


def event_type_badge(event_type: str) -> str:
    """Return styled HTML badge for real-time scan event types."""
    ev = str(event_type).upper()
    colors = {
        "SCAN_CREATED": {"bg": "rgba(148, 163, 184, 0.15)", "text": "#cbd5e1", "border": "#64748b"},
        "SCAN_QUEUED": {"bg": "rgba(245, 158, 11, 0.15)", "text": "#fcd34d", "border": "#f59e0b"},
        "SCAN_STARTED": {"bg": "rgba(59, 130, 246, 0.15)", "text": "#93c5fd", "border": "#3b82f6"},
        "TARGET_VERIFIED": {"bg": "rgba(16, 185, 129, 0.15)", "text": "#6ee7b7", "border": "#10b981"},
        "TEST_STARTED": {"bg": "rgba(99, 102, 241, 0.15)", "text": "#a5b4fc", "border": "#6366f1"},
        "TEST_COMPLETED": {"bg": "rgba(16, 185, 129, 0.15)", "text": "#6ee7b7", "border": "#10b981"},
        "TEST_FAILED": {"bg": "rgba(239, 68, 68, 0.15)", "text": "#fca5a5", "border": "#ef4444"},
        "FINDING_CREATED": {"bg": "rgba(220, 38, 38, 0.25)", "text": "#f87171", "border": "#ef4444"},
        "CATEGORY_COMPLETED": {"bg": "rgba(168, 85, 247, 0.15)", "text": "#d8b4fe", "border": "#a855f7"},
        "SCAN_PROGRESS": {"bg": "rgba(14, 165, 233, 0.15)", "text": "#7dd3fc", "border": "#0ea5e9"},
        "SCAN_WARNING": {"bg": "rgba(245, 158, 11, 0.2)", "text": "#fcd34d", "border": "#f59e0b"},
        "SCAN_ERROR": {"bg": "rgba(239, 68, 68, 0.25)", "text": "#fca5a5", "border": "#ef4444"},
        "SCAN_CANCELLED": {"bg": "rgba(100, 116, 139, 0.2)", "text": "#94a3b8", "border": "#64748b"},
        "SCAN_COMPLETED": {"bg": "rgba(16, 185, 129, 0.2)", "text": "#6ee7b7", "border": "#10b981"},
        "SCAN_PARTIALLY_COMPLETED": {"bg": "rgba(245, 158, 11, 0.2)", "text": "#fcd34d", "border": "#f59e0b"},
    }
    style = colors.get(ev, {"bg": "rgba(100, 116, 139, 0.15)", "text": "#cbd5e1", "border": "#64748b"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style["border"]}; padding: 3px 8px; border-radius: 6px; '
        f'font-weight: 700; font-size: 0.72rem; letter-spacing: 0.03em;">{ev}</span>'
    )


def render_live_progress_bar(
    percentage: float,
    completed: int,
    total: int,
    current_category: Optional[str] = None,
    current_test_id: Optional[str] = None,
) -> None:
    """Render animated SaaS progress bar with live category and test telemetry."""
    pct = max(0.0, min(100.0, percentage))
    cat_info = f'• Testing Category: <code>{current_category}</code>' if current_category else ""
    test_info = f'• Test ID: <code>{current_test_id}</code>' if current_test_id else ""

    st.markdown(
        f"""
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 16px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div style="font-weight: 600; font-size: 0.9rem; color: #f8fafc; display: flex; align-items: center; gap: 8px;">
                    <span>⚡ Live Execution Progress</span>
                    <span style="font-size: 0.78rem; color: #94a3b8; font-weight: 400;">{completed} of {total} tests finished</span>
                </div>
                <div style="font-weight: 700; font-size: 1.1rem; color: #8b5cf6;">
                    {pct:.1f}%
                </div>
            </div>
            <div style="background: rgba(255, 255, 255, 0.06); border-radius: 9999px; height: 10px; width: 100%; overflow: hidden;">
                <div style="background: linear-gradient(90deg, #6366f1 0%, #8b5cf6 50%, #10b981 100%); height: 100%; width: {pct}%; transition: width 0.3s ease-in-out; border-radius: 9999px;"></div>
            </div>
            <div style="display: flex; gap: 12px; font-size: 0.78rem; color: #94a3b8; margin-top: 8px;">
                <span>Active Target</span>
                {cat_info}
                {test_info}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )



