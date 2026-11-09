"""Theme and CSS design system for LLM Security Scanner SaaS platform."""

CYBER_THEME_CSS = """
<style>
/* -------------------------------------------------------------
 * CORE COLOR PALETTE & CSS VARIABLES
 * ------------------------------------------------------------- */
:root {
    --bg-main: #090d16;
    --bg-surface: #111827;
    --bg-surface-elevated: #162036;
    --bg-surface-hover: #1c2640;
    --border-subtle: rgba(255, 255, 255, 0.08);
    --border-accent: rgba(99, 102, 241, 0.3);
    --accent-indigo: #6366f1;
    --accent-purple: #8b5cf6;
    --accent-blue: #3b82f6;
    --accent-cyan: #06b6d4;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --color-critical: #ef4444;
    --color-high: #f97316;
    --color-medium: #eab308;
    --color-low: #38bdf8;
    --color-info: #64748b;
    --color-success: #10b981;
}

/* -------------------------------------------------------------
 * BASE APP OVERRIDES
 * ------------------------------------------------------------- */
.stApp {
    background-color: var(--bg-main) !important;
    color: var(--text-primary) !important;
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif !important;
}

/* Header & Top Bar */
header[data-testid="stHeader"] {
    background-color: rgba(9, 13, 22, 0.85) !important;
    backdrop-filter: blur(12px) !important;
    border-bottom: 1px solid var(--border-subtle) !important;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #0b101c !important;
    border-right: 1px solid var(--border-subtle) !important;
}

section[data-testid="stSidebar"] .stMarkdown h2 {
    color: var(--text-primary) !important;
    font-size: 1.15rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
}

section[data-testid="stSidebar"] .stMarkdown p {
    color: var(--text-secondary) !important;
    font-size: 0.85rem !important;
}

/* Custom Scrollbar */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: var(--bg-main);
}
::-webkit-scrollbar-thumb {
    background: #1e293b;
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: #334155;
}

/* -------------------------------------------------------------
 * CARDS & SURFACES
 * ------------------------------------------------------------- */
.sec-card {
    background: linear-gradient(145deg, #111827 0%, #151d30 100%);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 20px 22px;
    margin-bottom: 18px;
    box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}

.sec-card:hover {
    border-color: rgba(99, 102, 241, 0.35);
    box-shadow: 0 8px 25px -4px rgba(99, 102, 241, 0.12);
}

.sec-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 10px;
}

.sec-card-title {
    font-size: 1.05rem;
    font-weight: 600;
    color: #f1f5f9;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* -------------------------------------------------------------
 * KPI METRICS CARDS
 * ------------------------------------------------------------- */
.kpi-container {
    background: linear-gradient(135deg, rgba(21, 29, 48, 0.95) 0%, rgba(17, 24, 39, 0.95) 100%);
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    height: 100%;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}

.kpi-container:hover {
    border-color: rgba(139, 92, 246, 0.35);
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.45);
}

.kpi-top-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
}

.kpi-label {
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
}

.kpi-icon-pill {
    width: 36px;
    height: 36px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.08);
}

.kpi-value {
    font-size: 2.1rem;
    font-weight: 700;
    line-height: 1.1;
    color: #ffffff;
    letter-spacing: -0.03em;
    margin-bottom: 8px;
}

.kpi-trend {
    font-size: 0.78rem;
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-muted);
}

.trend-pos {
    color: #10b981;
    font-weight: 600;
}

.trend-neg {
    color: #ef4444;
    font-weight: 600;
}

.trend-neutral {
    color: var(--text-secondary);
}

/* -------------------------------------------------------------
 * TOP NAVIGATION / BANNER BAR
 * ------------------------------------------------------------- */
.top-navbar {
    background: rgba(17, 24, 39, 0.85);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 12px 20px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
}

.navbar-brand {
    display: flex;
    align-items: center;
    gap: 12px;
}

.navbar-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -0.01em;
}

.navbar-badge {
    background: rgba(99, 102, 241, 0.15);
    border: 1px solid rgba(99, 102, 241, 0.3);
    color: #c7d2fe;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 9999px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.navbar-controls {
    display: flex;
    align-items: center;
    gap: 12px;
}

/* -------------------------------------------------------------
 * STATUS BADGES & PILLS
 * ------------------------------------------------------------- */
.pill-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

.pill-critical {
    background: rgba(239, 68, 68, 0.15);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.4);
}

.pill-high {
    background: rgba(249, 115, 22, 0.15);
    color: #fdba74;
    border: 1px solid rgba(249, 115, 22, 0.4);
}

.pill-medium {
    background: rgba(234, 179, 8, 0.15);
    color: #fde047;
    border: 1px solid rgba(234, 179, 8, 0.4);
}

.pill-low {
    background: rgba(56, 189, 248, 0.15);
    color: #7dd3fc;
    border: 1px solid rgba(56, 189, 248, 0.4);
}

.pill-info {
    background: rgba(100, 116, 139, 0.15);
    color: #cbd5e1;
    border: 1px solid rgba(100, 116, 139, 0.4);
}

.pill-success {
    background: rgba(16, 185, 129, 0.15);
    color: #6ee7b7;
    border: 1px solid rgba(16, 185, 129, 0.4);
}

/* -------------------------------------------------------------
 * RECOMMENDATION ITEM CARD
 * ------------------------------------------------------------- */
.rec-item {
    background: rgba(21, 29, 48, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-left: 4px solid var(--accent-indigo);
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 12px;
    transition: all 0.2s ease;
}

.rec-item:hover {
    background: rgba(26, 36, 60, 0.8);
    border-left-color: var(--accent-purple);
}

.rec-title {
    font-size: 0.95rem;
    font-weight: 600;
    color: #f1f5f9;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.rec-desc {
    font-size: 0.84rem;
    color: var(--text-secondary);
    line-height: 1.45;
}

/* -------------------------------------------------------------
 * EMPTY & ERROR STATES
 * ------------------------------------------------------------- */
.empty-box {
    text-align: center;
    padding: 45px 20px;
    border: 1px dashed rgba(255, 255, 255, 0.12);
    border-radius: 12px;
    background: rgba(17, 24, 39, 0.4);
    margin: 20px 0;
}

.empty-icon {
    font-size: 2.8rem;
    margin-bottom: 12px;
    opacity: 0.85;
}

.empty-title {
    font-size: 1.15rem;
    font-weight: 600;
    color: #f8fafc;
    margin-bottom: 6px;
}

.empty-subtitle {
    font-size: 0.88rem;
    color: var(--text-muted);
    max-width: 480px;
    margin: 0 auto 16px auto;
    line-height: 1.5;
}

/* -------------------------------------------------------------
 * STREAMLIT WIDGETS OVERRIDES
 * ------------------------------------------------------------- */
/* Form inputs */
div[data-baseweb="input"], div[data-baseweb="select"] {
    background-color: #0d1322 !important;
    border-color: rgba(255, 255, 255, 0.1) !important;
    border-radius: 8px !important;
    color: #ffffff !important;
}

div[data-baseweb="input"]:focus-within {
    border-color: var(--accent-indigo) !important;
    box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2) !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%) !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    padding: 0.55rem 1.25rem !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    box-shadow: 0 2px 8px rgba(79, 70, 229, 0.3) !important;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%) !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4) !important;
}

.stButton > button:active {
    transform: translateY(0px) !important;
}

/* Secondary Button styling */
.stButton > button[kind="secondary"] {
    background: rgba(255, 255, 255, 0.05) !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    color: #cbd5e1 !important;
    box-shadow: none !important;
}

.stButton > button[kind="secondary"]:hover {
    background: rgba(255, 255, 255, 0.1) !important;
    color: #ffffff !important;
}

/* Expanders */
div[data-testid="stExpander"] {
    background: #111827 !important;
    border: 1px solid var(--border-subtle) !important;
    border-radius: 10px !important;
    margin-bottom: 12px !important;
    overflow: hidden !important;
}

div[data-testid="stExpander"]:hover {
    border-color: rgba(99, 102, 241, 0.3) !important;
}

/* Dataframe styling */
div[data-testid="stDataFrame"] {
    border: 1px solid var(--border-subtle) !important;
    border-radius: 10px !important;
    overflow: hidden !important;
}

/* Sidebar Radio Buttons (Menu Navigation) */
div[data-testid="stSidebar"] div[role="radiogroup"] > label {
    padding: 8px 12px !important;
    border-radius: 8px !important;
    margin-bottom: 3px !important;
    transition: all 0.15s ease !important;
}

div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background: rgba(255, 255, 255, 0.05) !important;
}

/* Alert Boxes */
div[data-testid="stAlert"] {
    background: rgba(17, 24, 39, 0.95) !important;
    border: 1px solid var(--border-subtle) !important;
    border-radius: 10px !important;
    color: var(--text-primary) !important;
}

/* -------------------------------------------------------------
 * RESPONSIVENESS
 * ------------------------------------------------------------- */
@media (max-width: 768px) {
    .kpi-value {
        font-size: 1.6rem;
    }
    .top-navbar {
        flex-direction: column;
        align-items: flex-start;
    }
    .sec-card {
        padding: 14px;
    }
}
</style>
"""


def inject_custom_theme() -> None:
    """Inject premium cybersecurity SaaS styling into Streamlit DOM."""
    import streamlit as st
    st.markdown(CYBER_THEME_CSS, unsafe_allow_html=True)

