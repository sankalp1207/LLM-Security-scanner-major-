"""UI components, metrics cards, and badge styling for Streamlit dashboard."""

import streamlit as st


def render_header(title: str, subtitle: str) -> None:
    """Render standardized dashboard page header."""
    st.markdown(
        f"""
        <div style="margin-bottom: 25px;">
            <h1 style="margin-bottom: 0px; font-weight: 700; color: #1e293b;">{title}</h1>
            <p style="color: #64748b; font-size: 1.05rem; margin-top: 4px;">{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    """Return colored HTML badge for a vulnerability severity."""
    sev = str(severity).upper()
    colors = {
        "CRITICAL": {"bg": "#fee2e2", "text": "#991b1b", "border": "#ef4444"},
        "HIGH": {"bg": "#ffedd5", "text": "#9a3412", "border": "#f97316"},
        "MEDIUM": {"bg": "#fef9c3", "text": "#854d0e", "border": "#eab308"},
        "LOW": {"bg": "#e0f2fe", "text": "#075985", "border": "#38bdf8"},
        "INFORMATIONAL": {"bg": "#f1f5f9", "text": "#475569", "border": "#94a3b8"},
    }
    style = colors.get(sev, {"bg": "#f1f5f9", "text": "#475569", "border": "#94a3b8"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'border: 1px solid {style["border"]}; padding: 3px 10px; border-radius: 9999px; '
        f'font-weight: 600; font-size: 0.8rem; text-transform: uppercase;">{sev}</span>'
    )


def status_badge(status: str) -> str:
    """Return colored HTML badge for execution status."""
    st_val = str(status).upper()
    colors = {
        "COMPLETED": {"bg": "#dcfce7", "text": "#166534"},
        "RUNNING": {"bg": "#dbeafe", "text": "#1e40af"},
        "FAILED": {"bg": "#fee2e2", "text": "#991b1b"},
        "PARTIALLY_COMPLETED": {"bg": "#fef3c7", "text": "#92400e"},
        "RETEST_PASSED": {"bg": "#dcfce7", "text": "#166534"},
        "RETEST_FAILED": {"bg": "#fee2e2", "text": "#991b1b"},
        "NOT_RETESTED": {"bg": "#f1f5f9", "text": "#475569"},
    }
    style = colors.get(st_val, {"bg": "#f1f5f9", "text": "#475569"})
    return (
        f'<span style="background-color: {style["bg"]}; color: {style["text"]}; '
        f'padding: 3px 8px; border-radius: 6px; font-weight: 600; font-size: 0.8rem;">{st_val}</span>'
    )
