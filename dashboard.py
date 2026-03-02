"""
PhishGuard Streamlit Dashboard
==============================
Interactive web interface for email security analysis.
Dark cybersecurity theme — single dark mode only.
"""

import streamlit as st
import pandas as pd
import json
import os
import sys
from datetime import datetime

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.email_fetcher import EmailFetcher
from modules.analyzer_engine import PhishGuardAnalyzer
from config import API_KEYS, CACHE_CONFIG, DEMO_MODE, API_STATUS

# ── Page Configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard — Email Security Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Cybersecurity Dark Theme CSS ─────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');

    * { font-family: 'Inter', sans-serif; }

    /* ══════════════════════════════════════════════════════════
       FORCE DARK BACKGROUND EVERYWHERE
       ══════════════════════════════════════════════════════════ */
    .stApp,
    .main,
    .main .block-container,
    section[data-testid="stAppViewContainer"],
    [data-testid="stAppViewContainer"],
    header[data-testid="stHeader"],
    [data-testid="stBottomBlockContainer"],
    footer {
        background-color: #050a05 !important;
        color: #c9d1d9 !important;
    }

    /* ── Sidebar ─────────────────────────────────────────── */
    [data-testid="stSidebar"],
    [data-testid="stSidebar"] > div {
        background-color: #080d08 !important;
        border-right: 1px solid #0f1f0f !important;
    }
    [data-testid="stSidebar"] * { color: #c9d1d9; }

    /* ══════════════════════════════════════════════════════════
       TYPOGRAPHY
       ══════════════════════════════════════════════════════════ */
    .main-header {
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00ff41 0%, #00cc33 50%, #00994d 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.3rem;
        letter-spacing: -0.02em;
    }
    .subheader {
        font-size: 1.05rem;
        color: #58a558;
        font-weight: 400;
        letter-spacing: 0.03em;
    }

    /* General text — make sure all p, span, label, div text is readable */
    p, span, label, li { color: #c9d1d9; }
    strong, b { color: #e6edf3; }
    h1, h2, h3, h4, h5, h6 { color: #e6edf3 !important; }

    /* ── Captions ─────────────────────────────────────────── */
    .stCaption, [data-testid="stCaptionContainer"],
    [data-testid="stCaptionContainer"] * {
        color: #8b949e !important;
    }

    /* ══════════════════════════════════════════════════════════
       STREAMLIT ALERT BOXES (st.info, st.success, st.warning, st.error)
       — the #1 visibility problem on dark themes
       ══════════════════════════════════════════════════════════ */
    /* Base: all alerts */
    [data-testid="stAlert"],
    [data-testid="stNotification"],
    .stAlert {
        border-radius: 10px !important;
        color: #c9d1d9 !important;
    }
    [data-testid="stAlert"] p,
    [data-testid="stAlert"] span,
    [data-testid="stNotification"] p,
    [data-testid="stNotification"] span {
        color: #c9d1d9 !important;
    }

    /* st.info — dark blue-green */
    [data-testid="stAlert"][data-baseweb*="info"],
    div[role="alert"]:has(> div > svg[data-testid="stIconMaterial"]) {
        background-color: #0d1a1a !important;
        border: 1px solid #1b3b3b !important;
    }

    /* Override ALL alert variants by kind attribute & color */
    .element-container [data-testid="stAlert"] {
        background-color: #0d1117 !important;
        border: 1px solid #1b2b1b !important;
    }

    /* st.success */
    .stSuccess, div[data-testid="stAlert"]:has(svg[fill="#09AB3B"]),
    div[data-testid="stAlert"]:has(svg[title="success"]) {
        background-color: #061a06 !important;
        border: 1px solid #0f3b0f !important;
    }
    .stSuccess p, .stSuccess span { color: #7ee87e !important; }

    /* st.warning */
    .stWarning, div[data-testid="stAlert"]:has(svg[fill="#FACA2B"]),
    div[data-testid="stAlert"]:has(svg[title="warning"]) {
        background-color: #1a1406 !important;
        border: 1px solid #3b2f0f !important;
    }
    .stWarning p, .stWarning span { color: #f0d060 !important; }

    /* st.error */
    .stError, div[data-testid="stAlert"]:has(svg[fill="#FF4B4B"]),
    div[data-testid="stAlert"]:has(svg[title="error"]) {
        background-color: #1a0606 !important;
        border: 1px solid #3b0f0f !important;
    }
    .stError p, .stError span { color: #f88 !important; }

    /* ══════════════════════════════════════════════════════════
       DATAFRAME / TABLE — force dark
       ══════════════════════════════════════════════════════════ */
    .stDataFrame { border-radius: 12px; overflow: hidden; }

    /* Glide data grid (Streamlit's default table renderer) */
    [data-testid="stDataFrame"] canvas + div,
    [data-testid="stDataFrame"] [role="grid"],
    [data-testid="stDataFrame"],
    .dvn-scroller,
    .glideDataEditor {
        background-color: #0d1117 !important;
    }

    /* Fallback: if rendered as HTML table */
    .stDataFrame table,
    .stDataFrame thead,
    .stDataFrame tbody,
    .stDataFrame th,
    .stDataFrame td {
        background-color: #0d1117 !important;
        color: #c9d1d9 !important;
        border-color: #1b2b1b !important;
    }
    .stDataFrame th {
        background-color: #111b11 !important;
        color: #58a558 !important;
        font-weight: 600;
    }
    .stDataFrame tr:hover td {
        background-color: #0f1f0f !important;
    }

    /* ══════════════════════════════════════════════════════════
       CODE BLOCKS (st.code)
       ══════════════════════════════════════════════════════════ */
    code, pre, .stCodeBlock,
    [data-testid="stCode"],
    .stCode pre, .stCode code {
        font-family: 'JetBrains Mono', monospace !important;
        color: #00ff41 !important;
        background-color: #0d1117 !important;
        border: 1px solid #1b2b1b;
        border-radius: 8px;
    }
    /* Copy button inside code blocks */
    [data-testid="stCode"] button {
        color: #8b949e !important;
    }

    /* ══════════════════════════════════════════════════════════
       PROGRESS BAR
       ══════════════════════════════════════════════════════════ */
    .stProgress > div > div { border-radius: 10px; }
    .stProgress > div > div > div { border-radius: 10px; }

    /* Progress bar text ("Risk Level: 75%") */
    .stProgress p, .stProgress span,
    [data-testid="stProgressBarText"],
    .stProgress [data-testid="stMarkdownContainer"] p {
        color: #c9d1d9 !important;
        font-weight: 500;
    }

    /* ══════════════════════════════════════════════════════════
       INPUTS — text input, text area, file uploader, radio, selectbox
       ══════════════════════════════════════════════════════════ */
    /* Text input / text area */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stTextInput input,
    .stTextArea textarea {
        background-color: #0d1117 !important;
        border: 1px solid #1b2b1b !important;
        color: #c9d1d9 !important;
        border-radius: 10px !important;
    }
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #00ff4140 !important;
        box-shadow: 0 0 10px rgba(0,255,65,0.08) !important;
    }
    .stTextInput label, .stTextArea label {
        color: #8b949e !important;
    }

    /* File uploader */
    [data-testid="stFileUploader"],
    [data-testid="stFileUploader"] > div,
    [data-testid="stFileUploader"] section,
    [data-testid="stFileUploader"] section > div,
    [data-testid="stFileDropzoneInstructions"] {
        background-color: #0d1117 !important;
        border-color: #1b2b1b !important;
        color: #8b949e !important;
    }
    [data-testid="stFileUploader"] section {
        border: 1px dashed #1b3b1b !important;
        border-radius: 10px !important;
    }
    [data-testid="stFileUploader"] small,
    [data-testid="stFileUploader"] span,
    [data-testid="stFileUploader"] p,
    [data-testid="stFileDropzoneInstructions"] span,
    [data-testid="stFileDropzoneInstructions"] div {
        color: #8b949e !important;
    }
    /* Uploaded file info chip */
    [data-testid="stFileUploaderFile"],
    [data-testid="stFileUploaderFile"] > div {
        background-color: #111b11 !important;
        border: 1px solid #1b2b1b !important;
        border-radius: 8px !important;
    }
    [data-testid="stFileUploaderFile"] span,
    [data-testid="stFileUploaderFile"] small {
        color: #c9d1d9 !important;
    }
    [data-testid="stFileUploaderFile"] button {
        color: #8b949e !important;
    }

    /* Radio buttons */
    .stRadio > div { color: #c9d1d9 !important; }
    .stRadio label { color: #c9d1d9 !important; }
    .stRadio label span { color: #c9d1d9 !important; }
    .stRadio [role="radiogroup"] label {
        background-color: transparent !important;
    }

    /* Selectbox / Multiselect */
    [data-baseweb="select"] > div,
    [data-baseweb="select"] input {
        background-color: #0d1117 !important;
        border-color: #1b2b1b !important;
        color: #c9d1d9 !important;
    }
    [data-baseweb="popover"],
    [data-baseweb="menu"],
    [data-baseweb="menu"] li {
        background-color: #0d1117 !important;
        color: #c9d1d9 !important;
    }
    [data-baseweb="menu"] li:hover {
        background-color: #0f1f0f !important;
    }

    /* ══════════════════════════════════════════════════════════
       BUTTONS
       ══════════════════════════════════════════════════════════ */
    .stButton > button {
        border-radius: 10px !important;
        font-weight: 600 !important;
        border: 1px solid #1b2b1b !important;
        background-color: #0d1117 !important;
        color: #c9d1d9 !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button:hover {
        border-color: #00ff4150 !important;
        box-shadow: 0 0 20px rgba(0,255,65,0.1) !important;
        color: #00ff41 !important;
    }
    .stButton > button[kind="primary"],
    .stButton > button[data-testid="stBaseButton-primary"] {
        background: linear-gradient(135deg, #00cc33 0%, #009922 100%) !important;
        color: #000 !important;
        border: none !important;
        font-weight: 700 !important;
    }
    .stButton > button[kind="primary"]:hover,
    .stButton > button[data-testid="stBaseButton-primary"]:hover {
        box-shadow: 0 0 30px rgba(0,255,65,0.25) !important;
    }

    /* Download button */
    .stDownloadButton > button {
        background: #0d1117 !important;
        color: #00ff41 !important;
        border: 1px solid #1b2b1b !important;
        border-radius: 10px !important;
    }
    .stDownloadButton > button:hover {
        border-color: #00ff4150 !important;
        box-shadow: 0 0 20px rgba(0,255,65,0.1) !important;
    }

    /* ══════════════════════════════════════════════════════════
       SPINNER
       ══════════════════════════════════════════════════════════ */
    [data-testid="stSpinner"] > div,
    .stSpinner > div {
        color: #00ff41 !important;
    }
    [data-testid="stSpinner"] p {
        color: #c9d1d9 !important;
    }

    /* ══════════════════════════════════════════════════════════
       DIVIDERS & SEPARATORS
       ══════════════════════════════════════════════════════════ */
    hr, [data-testid="stDivider"] {
        border-color: #1b2b1b !important;
        opacity: 0.6;
    }

    /* ══════════════════════════════════════════════════════════
       TABS
       ══════════════════════════════════════════════════════════ */
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] { color: #8b949e; border-radius: 8px; }
    .stTabs [data-baseweb="tab"]:hover { color: #00ff41; }
    .stTabs [data-baseweb="tab"][aria-selected="true"] { color: #00ff41 !important; }

    /* ══════════════════════════════════════════════════════════
       EXPANDER
       ══════════════════════════════════════════════════════════ */
    .streamlit-expanderHeader,
    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] summary span {
        color: #c9d1d9 !important;
    }
    [data-testid="stExpander"] {
        background-color: #0d1117 !important;
        border: 1px solid #1b2b1b !important;
        border-radius: 10px !important;
    }

    /* ══════════════════════════════════════════════════════════
       TOOLTIP / POPOVER
       ══════════════════════════════════════════════════════════ */
    [data-baseweb="tooltip"] > div {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #1b2b1b !important;
    }

    /* ══════════════════════════════════════════════════════════
       METRIC CARD
       ══════════════════════════════════════════════════════════ */
    .metric-card {
        background: linear-gradient(160deg, #0d1117 0%, #080d08 100%);
        border-radius: 16px;
        padding: 24px;
        text-align: center;
        border: 1px solid #1b2b1b;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.02);
        transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
    }
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 0 35px rgba(0, 255, 65, 0.07);
        border-color: rgba(0, 255, 65, 0.2);
    }
    .metric-card h4 {
        color: #58a558;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin-bottom: 10px;
        font-weight: 500;
    }
    .metric-card p, .metric-card span { color: #c9d1d9; }

    /* ══════════════════════════════════════════════════════════
       THREAT LEVEL COLORS
       ══════════════════════════════════════════════════════════ */
    .threat-high   { color: #f85149; font-weight: 700; }
    .threat-medium { color: #d29922; font-weight: 700; }
    .threat-low    { color: #00ff41; font-weight: 700; }

    /* ══════════════════════════════════════════════════════════
       SCORE CIRCLE
       ══════════════════════════════════════════════════════════ */
    .score-circle {
        width: 130px; height: 130px;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 2.2rem; font-weight: 700;
        margin: 0 auto;
        font-family: 'JetBrains Mono', monospace;
    }
    .score-high {
        background: radial-gradient(circle, #1a0808 0%, #0d0303 100%);
        color: #f85149; border: 3px solid #f85149;
        box-shadow: 0 0 40px rgba(248, 81, 73, 0.15), inset 0 0 20px rgba(248, 81, 73, 0.05);
    }
    .score-medium {
        background: radial-gradient(circle, #1a1408 0%, #0d0a03 100%);
        color: #d29922; border: 3px solid #d29922;
        box-shadow: 0 0 40px rgba(210, 153, 34, 0.15), inset 0 0 20px rgba(210, 153, 34, 0.05);
    }
    .score-low {
        background: radial-gradient(circle, #081a08 0%, #030d03 100%);
        color: #00ff41; border: 3px solid #00ff41;
        box-shadow: 0 0 40px rgba(0, 255, 65, 0.15), inset 0 0 20px rgba(0, 255, 65, 0.05);
    }

    /* ══════════════════════════════════════════════════════════
       FEATURE CARD (Welcome page)
       ══════════════════════════════════════════════════════════ */
    .feature-card {
        background: #0d1117;
        border-radius: 14px;
        padding: 28px 24px;
        border: 1px solid #1b2b1b;
        transition: all 0.3s ease;
        margin-bottom: 14px;
    }
    .feature-card:hover {
        box-shadow: 0 0 30px rgba(0, 255, 65, 0.06);
        border-color: rgba(0, 255, 65, 0.25);
    }
    .feature-card h4 { color: #e6edf3; margin-bottom: 8px; font-size: 1.05rem; }
    .feature-card p  { color: #8b949e; font-size: 0.9rem; line-height: 1.6; margin: 0; }
    .feature-num {
        font-family: 'JetBrains Mono', monospace;
        color: #3d8b3d;
        font-size: 0.75rem;
        letter-spacing: 0.1em;
        margin-bottom: 10px;
    }

    /* ══════════════════════════════════════════════════════════
       AUTH BADGES
       ══════════════════════════════════════════════════════════ */
    .auth-pass {
        background: linear-gradient(135deg, #061a06 0%, #0a220a 100%);
        color: #00ff41; padding: 14px 16px; border-radius: 12px;
        font-weight: 600; text-align: center; border: 1px solid #00ff4125;
    }
    .auth-fail {
        background: linear-gradient(135deg, #1a0606 0%, #220a0a 100%);
        color: #f85149; padding: 14px 16px; border-radius: 12px;
        font-weight: 600; text-align: center; border: 1px solid #f8514925;
    }
    .auth-neutral {
        background: linear-gradient(135deg, #111318 0%, #161b22 100%);
        color: #8b949e; padding: 14px 16px; border-radius: 12px;
        font-weight: 600; text-align: center; border: 1px solid #30363d;
    }

    /* ══════════════════════════════════════════════════════════
       THREAT BADGES
       ══════════════════════════════════════════════════════════ */
    .threat-badge {
        display: inline-block; padding: 6px 16px; border-radius: 20px;
        font-size: 0.85rem; font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-high   { background: #f8514918; color: #f85149; border: 1px solid #f8514940; }
    .badge-medium { background: #d2992218; color: #d29922; border: 1px solid #d2992240; }
    .badge-low    { background: #00ff4118; color: #00ff41; border: 1px solid #00ff4140; }

    /* ══════════════════════════════════════════════════════════
       SIDEBAR SECTIONS
       ══════════════════════════════════════════════════════════ */
    .sidebar-section {
        background: #0d1117;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
        border: 1px solid #1b2b1b;
    }

    /* ══════════════════════════════════════════════════════════
       HISTORY ITEMS
       ══════════════════════════════════════════════════════════ */
    .history-item {
        background: #0a0f0a; border-radius: 8px;
        padding: 10px 14px; margin-bottom: 8px;
        border-left: 4px solid #1b2b1b;
        font-size: 0.88rem; color: #8b949e;
    }
    .history-item strong { color: #e6edf3; }
    .history-item small  { color: #58a558; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; }
    .history-high   { border-left-color: #f85149; }
    .history-medium { border-left-color: #d29922; }
    .history-low    { border-left-color: #00ff41; }

    /* ══════════════════════════════════════════════════════════
       WELCOME HERO
       ══════════════════════════════════════════════════════════ */
    .welcome-hero {
        background: linear-gradient(160deg, #0d1117 0%, #081408 40%, #0d1117 100%);
        padding: 55px 40px; border-radius: 20px;
        text-align: center; margin-bottom: 32px;
        border: 1px solid #1b2b1b;
        position: relative; overflow: hidden;
    }
    .welcome-hero::before {
        content: '';
        position: absolute; top: -40%; left: 20%; width: 60%; height: 180%;
        background: radial-gradient(ellipse, rgba(0,255,65,0.04) 0%, transparent 70%);
        pointer-events: none;
    }
    .welcome-hero h1 {
        color: #00ff41 !important; font-size: 2.6rem;
        margin-bottom: 12px; position: relative;
        text-shadow: 0 0 40px rgba(0,255,65,0.15);
    }
    .welcome-hero p {
        color: #58a558; font-size: 1.1rem;
        position: relative; max-width: 600px; margin: 0 auto;
    }

    /* ══════════════════════════════════════════════════════════
       INDICATOR ROWS (Threat Indicators section)
       ══════════════════════════════════════════════════════════ */
    .indicator-row {
        background: #0d1117;
        border: 1px solid #1b2b1b;
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 10px;
        display: flex;
        align-items: flex-start;
        gap: 12px;
    }
    .indicator-row.danger  { border-left: 4px solid #f85149; }
    .indicator-row.warning { border-left: 4px solid #d29922; }
    .indicator-row.safe    { border-left: 4px solid #00ff41; }
    .indicator-label { color: #8b949e; font-size: 0.82rem; }
    .indicator-value { color: #e6edf3; font-weight: 500; }

    /* ══════════════════════════════════════════════════════════
       STAT DISPLAY
       ══════════════════════════════════════════════════════════ */
    .stat-num {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2.2rem; font-weight: 700;
        color: #00ff41;
        text-shadow: 0 0 20px rgba(0,255,65,0.2);
    }
    .stat-label {
        color: #58a558;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin-top: 2px;
    }

    /* ══════════════════════════════════════════════════════════
       SECTION HEADER
       ══════════════════════════════════════════════════════════ */
    .section-hdr {
        display: flex; align-items: center; gap: 10px;
        margin-bottom: 18px;
    }
    .section-hdr .icon { font-size: 1.3rem; }
    .section-hdr .text {
        color: #e6edf3; font-size: 1.2rem; font-weight: 600;
    }
    .section-hdr .line {
        flex: 1; height: 1px;
        background: linear-gradient(90deg, #1b2b1b 0%, transparent 100%);
    }

    /* ══════════════════════════════════════════════════════════
       SCROLLBAR (for a polished look)
       ══════════════════════════════════════════════════════════ */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #050a05; }
    ::-webkit-scrollbar-thumb { background: #1b2b1b; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #2b3b2b; }

    /* ══════════════════════════════════════════════════════════
       MARKDOWN rendered inside st.markdown — make bold visible
       ══════════════════════════════════════════════════════════ */
    [data-testid="stMarkdownContainer"] p {
        color: #c9d1d9;
    }
    [data-testid="stMarkdownContainer"] strong {
        color: #e6edf3;
    }
    [data-testid="stMarkdownContainer"] a {
        color: #58a558;
    }

    /* ══════════════════════════════════════════════════════════
       STREAMLIT NATIVE METRIC (st.metric)
       ══════════════════════════════════════════════════════════ */
    [data-testid="stMetric"] label { color: #58a558 !important; }
    [data-testid="stMetric"] [data-testid="stMetricValue"] { color: #e6edf3 !important; }
    [data-testid="stMetric"] [data-testid="stMetricDelta"] { color: #8b949e !important; }
</style>
""", unsafe_allow_html=True)


# ── Session State ────────────────────────────────────────────────────────────
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = PhishGuardAnalyzer(
        api_keys=API_KEYS,
        cache_file=CACHE_CONFIG['storage']
    )

if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None

if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []


# ── Helper Functions ─────────────────────────────────────────────────────────

def get_threat_color(score):
    if score >= 71:
        return "🔴"
    elif score >= 31:
        return "🟠"
    return "🟢"


def get_score_circle_class(score):
    if score >= 71:
        return "score-high"
    elif score >= 31:
        return "score-medium"
    return "score-low"


def get_badge_class(score):
    if score >= 71:
        return "badge-high"
    elif score >= 31:
        return "badge-medium"
    return "badge-low"


def get_country_flag(country_code):
    flags = {
        'US': '🇺🇸', 'RU': '🇷🇺', 'CN': '🇨🇳', 'GB': '🇬🇧', 'DE': '🇩🇪',
        'FR': '🇫🇷', 'JP': '🇯🇵', 'IN': '🇮🇳', 'BR': '🇧🇷', 'CA': '🇨🇦',
        'AU': '🇦🇺', 'KR': '🇰🇷', 'NL': '🇳🇱', 'SG': '🇸🇬',
        'Private': '🏠', 'Unknown': '❓'
    }
    return flags.get(country_code, '🌐')


def section_header(icon, text):
    """Render a styled section header"""
    st.markdown(f"""
    <div class="section-hdr">
        <span class="icon">{icon}</span>
        <span class="text">{text}</span>
        <span class="line"></span>
    </div>
    """, unsafe_allow_html=True)


# ── Parse Pasted Headers ─────────────────────────────────────────────────────

def _build_email_from_pasted_headers(pasted: str) -> bytes:
    """
    Build a valid RFC-822 email from pasted header text.

    Instead of wrapping the pasted content in dummy From/To/Subject values
    (which causes false-positive lookalike detection on 'example.com'),
    this function:
      1. Extracts real From, To, Subject, Received, etc. from the paste
      2. Fills in only truly missing headers with safe placeholders
      3. Puts everything remaining into the body for reference
    """
    import re

    lines = pasted.strip().splitlines()

    # ── Unfold continuation lines ───────────────────────────────────
    #    RFC 2822: continuation = starts with whitespace.
    #    Also handle a common copy-paste artefact: a bare <email@domain>
    #    on its own line right after a From/To header (no leading space).
    unfolded: list[str] = []
    BARE_EMAIL_RE = re.compile(r'^<[^>]+>$')

    for line in lines:
        stripped = line.strip()
        # Standard RFC continuation (leading whitespace)
        if line and line[0] in (' ', '\t') and unfolded:
            unfolded[-1] += ' ' + stripped
        # Bare <email> on its own line — merge into previous header
        elif BARE_EMAIL_RE.match(stripped) and unfolded:
            unfolded[-1] += ' ' + stripped
        else:
            unfolded.append(line)

    # ── Extract known headers ─────────────────────────────────────────
    known_headers: dict[str, list[str]] = {}
    body_lines: list[str] = []
    header_order: list[str] = []          # preserve original order
    hit_blank = False                     # track header/body separator

    HEADER_RE = re.compile(r'^([\w-]+)\s*:\s*(.*)', re.IGNORECASE)

    for line in unfolded:
        if not hit_blank and line.strip() == '':
            hit_blank = True
            continue

        if hit_blank:
            body_lines.append(line)
            continue

        m = HEADER_RE.match(line)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            norm = key.lower()
            if norm not in known_headers:
                known_headers[norm] = []
                header_order.append(key)
            known_headers[norm].append(val)
        else:
            # Not a valid header line – treat as body
            body_lines.append(line)

    # ── Build the email ───────────────────────────────────────────────
    email_lines: list[str] = []

    def _emit(name: str, value: str):
        email_lines.append(f'{name}: {value}')

    # Received headers first (may be multiple)
    for val in known_headers.get('received', []):
        _emit('Received', val)

    # Core identity headers – use parsed values or safe fallbacks
    _from = (known_headers.get('from', [''])[0]
             or known_headers.get('sender', [''])[0])
    _to = known_headers.get('to', [''])[0]
    _subject = known_headers.get('subject', [''])[0]
    _return_path = known_headers.get('return-path', [''])[0]
    _date = known_headers.get('date', [''])[0]
    _msg_id = known_headers.get('message-id', [''])[0]

    if _from:
        _emit('From', _from)
    if _to:
        _emit('To', _to)
    if _subject:
        _emit('Subject', _subject)
    else:
        _emit('Subject', 'Pasted Email')
    if _return_path:
        _emit('Return-Path', _return_path)
    if _date:
        _emit('Date', _date)
    if _msg_id:
        _emit('Message-ID', _msg_id)

    # Emit any remaining headers we haven't handled yet
    skip_keys = {
        'received', 'from', 'to', 'subject', 'return-path',
        'date', 'message-id', 'sender',
    }
    for key in header_order:
        if key.lower() not in skip_keys:
            for val in known_headers[key.lower()]:
                _emit(key, val)

    # Blank line separating headers from body
    email_lines.append('')

    # Put any remaining body / un-parsed lines in the body
    if body_lines:
        email_lines.extend(body_lines)

    return '\n'.join(email_lines).encode('utf-8')


# ── Header ───────────────────────────────────────────────────────────────────

def render_header():
    col1, col2 = st.columns([4, 1])

    with col1:
        st.markdown('<p class="main-header">🛡️ PhishGuard</p>', unsafe_allow_html=True)
        st.markdown(
            '<p class="subheader">Advanced Email Security &amp; Phishing Detection Platform</p>',
            unsafe_allow_html=True,
        )

    with col2:
        if DEMO_MODE:
            st.markdown(
                '<div style="background:#d2992215;color:#d29922;padding:8px 14px;'
                'border-radius:10px;border:1px solid #d2992230;text-align:center;'
                'font-size:0.85rem;font-weight:600;font-family:\'JetBrains Mono\',monospace;">'
                '⚠ DEMO MODE</div>',
                unsafe_allow_html=True,
            )
            st.caption("No API keys — using offline heuristics only")
        else:
            live_apis = [k for k, v in API_STATUS.items() if v == 'live']
            demo_apis = [k for k, v in API_STATUS.items() if v == 'demo']
            st.markdown(
                '<div style="background:#00ff4115;color:#00ff41;padding:8px 14px;'
                'border-radius:10px;border:1px solid #00ff4130;text-align:center;'
                'font-size:0.85rem;font-weight:600;font-family:\'JetBrains Mono\',monospace;">'
                f'● {len(live_apis)} API{"s" if len(live_apis) != 1 else ""} Connected</div>',
                unsafe_allow_html=True,
            )
            st.caption(f"Live: {', '.join(live_apis)}" + (f" · Offline: {', '.join(demo_apis)}" if demo_apis else ""))


# ── Sidebar ──────────────────────────────────────────────────────────────────

def render_sidebar():
    st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.sidebar.markdown(
        '<p style="color:#00ff41;font-weight:600;font-size:1rem;margin-bottom:12px;">'
        '📧 Email Input</p>',
        unsafe_allow_html=True,
    )

    input_method = st.sidebar.radio(
        "Choose Input Method:",
        ["📁 Upload .eml File", "📋 Paste Email Headers", "🎯 Sample Analysis"],
        label_visibility="collapsed",
    )

    email_data = None

    if input_method == "📁 Upload .eml File":
        uploaded_file = st.sidebar.file_uploader(
            "Upload .eml file",
            type=['eml'],
            help="Upload an email file exported from your email client",
            label_visibility="collapsed",
        )
        if uploaded_file:
            email_data = uploaded_file.read()
            st.sidebar.success(f"✅ Loaded: {uploaded_file.name}")

    elif input_method == "📋 Paste Email Headers":
        st.sidebar.info("Paste raw email headers including Received, From, To, etc.")
        pasted_headers = st.sidebar.text_area(
            "Email Headers:",
            height=200,
            placeholder="Received: from mail.example.com...\nFrom: sender@example.com...",
        )
        if pasted_headers:
            email_data = _build_email_from_pasted_headers(pasted_headers)

    else:
        st.sidebar.markdown(
            '<p style="color:#8b949e;font-size:0.88rem;">Analyze a sample phishing email for demonstration</p>',
            unsafe_allow_html=True,
        )
        if st.sidebar.button("🎯 Load Sample Phishing Email", use_container_width=True):
            email_data = create_sample_email()
            st.sidebar.success("✅ Sample loaded!")

    st.sidebar.markdown('</div>', unsafe_allow_html=True)

    # Analyze button
    st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    if email_data and st.sidebar.button("⚡ Analyze Email", type="primary", use_container_width=True):
        with st.spinner("🔍 Scanning email security…"):
            result = st.session_state.analyzer.analyze_eml_bytes(email_data)
            if result:
                st.session_state.analysis_result = result
                st.session_state.analysis_history.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'subject': result.get('subject', 'Unknown')[:30],
                    'score': result.get('threat_score', 0),
                    'classification': result.get('classification', 'UNKNOWN'),
                })
                st.rerun()
            else:
                st.sidebar.error("❌ Failed to parse email")

    if st.session_state.analysis_result and st.sidebar.button("🗑️ Clear Results", use_container_width=True):
        st.session_state.analysis_result = None
        st.rerun()
    st.sidebar.markdown('</div>', unsafe_allow_html=True)

    # History
    if st.session_state.analysis_history:
        st.sidebar.markdown("---")
        st.sidebar.markdown(
            '<p style="color:#00ff41;font-weight:600;font-size:1rem;margin-bottom:12px;">'
            '📊 Analysis History</p>',
            unsafe_allow_html=True,
        )
        for item in st.session_state.analysis_history[-5:]:
            score = item['score']
            hist_cls = "history-high" if score >= 71 else "history-medium" if score >= 31 else "history-low"
            st.sidebar.markdown(
                f'<div class="history-item {hist_cls}">'
                f'<small>{item["timestamp"]}</small><br>'
                f'<strong>{item["subject"]}</strong><br>'
                f'Score: <b>{score}</b> · {item["classification"][:15]}'
                f'</div>',
                unsafe_allow_html=True,
            )


# ── Sample Email ─────────────────────────────────────────────────────────────

def create_sample_email() -> bytes:
    return b"""Message-ID: <phish-sample-123@evil.com>
Date: Fri, 07 Feb 2026 14:22:58 +0000
From: PayPal Security <security@paypa1-verify.com>
To: victim@company.com
Subject: Urgent: Your Account Has Been Suspended
Return-Path: <bounce@evil-server.ru>
Received: from mail.evil-server.ru (unknown [45.33.22.11])
    by mx.google.com with ESMTP id abc123
    for <victim@company.com>; Fri, 07 Feb 2026 14:22:58 +0000
Received: from localhost (localhost [127.0.0.1])
    by mail.evil-server.ru with ESMTPS id xyz789;
    Fri, 07 Feb 2026 14:22:55 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=paypa1-verify.com; s=default;
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=evil-server.ru;
    dkim=none;
    dmarc=fail (p=REJECT) header.from=paypa1-verify.com
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h1>PayPal Security Alert</h1>
<p>Dear Customer,</p>
<p>We detected unusual activity on your account. Your account has been <b>suspended</b>.</p>
<p><a href="http://paypa1-verify.com/login">Click here immediately to verify your account</a></p>
<p>You must act within 24 hours or your account will be permanently closed.</p>
<p>Visible text: https://www.paypal.com/signin<br>
Actual link: http://paypa1-verify.com/login</p>
</body>
</html>
"""


# ── Render: Threat Score ─────────────────────────────────────────────────────

def render_threat_score(result):
    score = result.get('threat_score', 0)
    classification = result.get('classification', 'UNKNOWN')

    section_header("🎯", "Threat Assessment")

    col1, col2, col3, col4 = st.columns([1.5, 1, 1, 1])

    with col1:
        circle_cls = get_score_circle_class(score)
        st.markdown(f"""
        <div class="score-circle {circle_cls}">{score}</div>
        <p style="text-align:center;margin-top:12px;font-weight:600;color:#8b949e;
                  font-family:'JetBrains Mono',monospace;font-size:0.85rem;">
            THREAT SCORE
        </p>
        """, unsafe_allow_html=True)

    with col2:
        badge_cls = get_badge_class(score)
        st.markdown(f"""
        <div class="metric-card">
            <h4>Classification</h4>
            <span class="threat-badge {badge_cls}">{classification.replace('_', ' ')}</span>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        recommendation = "BLOCK" if score >= 71 else "REVIEW" if score >= 31 else "ACCEPT"
        rec_icon = "🔴" if recommendation == "BLOCK" else "🟠" if recommendation == "REVIEW" else "🟢"
        st.markdown(f"""
        <div class="metric-card">
            <h4>Recommendation</h4>
            <p style="font-size:1.2rem;font-weight:700;">{rec_icon} {recommendation}</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Analysis Time</h4>
            <p style="font-size:1.2rem;font-weight:700;color:#00ff41;">
                ⚡ {result.get('analysis_time_seconds', 0)}s
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.progress(score / 100, text=f"Risk Level: {score}%")


# ── Render: Email Metadata ───────────────────────────────────────────────────

def render_email_metadata(result):
    section_header("📨", "Email Metadata")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Message ID**")
        msg_id = result.get('message_id', 'N/A')
        st.code(msg_id[:60] + '…' if len(msg_id) > 60 else msg_id, language=None)

        st.markdown("**From (Display)**")
        st.info(result.get('from_header', 'N/A'))

        st.markdown("**To**")
        to_addr = result.get('to', 'N/A')
        st.info(to_addr[:50] + '…' if len(to_addr) > 50 else to_addr)

    with col2:
        envelope = result.get('from_envelope', '')
        header = result.get('from_header', '')

        if envelope and header and envelope not in header:
            st.markdown("**From (Envelope)**")
            st.error(f"{envelope}  ⚠️ MISMATCH DETECTED")
        else:
            st.markdown("**From (Envelope)**")
            st.info(envelope or 'N/A')

        st.markdown("**Subject**")
        st.info(result.get('subject', 'N/A'))

        st.markdown("**Timestamp**")
        st.info(result.get('timestamp', 'N/A'))


# ── Render: Authentication ───────────────────────────────────────────────────

def render_authentication_results(result):
    section_header("🔐", "Authentication Status")

    auth = result.get('authentication', {})

    col1, col2, col3 = st.columns(3)

    with col1:
        spf = auth.get('spf', {})
        spf_result = spf.get('result', 'none')
        if spf_result == 'pass':
            st.markdown('<div class="auth-pass">✅ SPF PASS</div>', unsafe_allow_html=True)
        elif spf_result in ['fail', 'softfail']:
            st.markdown(f'<div class="auth-fail">✖ SPF {spf_result.upper()}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="auth-neutral">⬚ SPF {spf_result.upper()}</div>', unsafe_allow_html=True)
        if spf.get('reason'):
            st.caption(spf['reason'])

    with col2:
        dkim = auth.get('dkim', {})
        dkim_result = dkim.get('result', 'none')
        if dkim_result == 'pass':
            st.markdown('<div class="auth-pass">✅ DKIM PASS</div>', unsafe_allow_html=True)
        elif dkim_result == 'fail':
            st.markdown('<div class="auth-fail">✖ DKIM FAIL</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="auth-neutral">⬚ DKIM {dkim_result.upper()}</div>', unsafe_allow_html=True)
        if dkim.get('selector'):
            st.caption(f"Selector: {dkim['selector']}")

    with col3:
        dmarc = auth.get('dmarc', {})
        dmarc_result = dmarc.get('policy', 'none')
        if dmarc_result in ['reject', 'quarantine']:
            st.markdown(
                f'<div class="auth-pass">✅ DMARC {dmarc_result.upper()}</div>',
                unsafe_allow_html=True,
            )
        elif dmarc_result == 'none':
            st.markdown('<div class="auth-neutral">⬚ DMARC NONE</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="auth-fail">✖ DMARC {dmarc_result.upper()}</div>',
                unsafe_allow_html=True,
            )
        if dmarc.get('percentage'):
            st.caption(f"Pct: {dmarc['percentage']}%")


# ── Render: Relay Path ───────────────────────────────────────────────────────

def render_relay_path(result):
    section_header("🌍", "Relay Path Analysis")

    relay_path = result.get('relay_path', [])
    if not relay_path:
        st.info("No relay path information available")
        return

    st.caption(result.get('relay_summary', ''))

    df_data = []
    for hop in relay_path:
        df_data.append({
            'Hop': hop.get('hop', ''),
            'IP': hop.get('ip', 'N/A'),
            'Hostname': (hop.get('hostname') or 'N/A')[:40],
            'Country': f"{hop.get('country', 'Unknown')} {get_country_flag(hop.get('country', ''))}",
            'ISP': (hop.get('isp') or 'Unknown')[:30],
            'Reputation': f"{hop.get('reputation_score', 0)}/100",
        })

    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True, hide_index=True)

    anomalies = result.get('relay_anomalies', [])
    if anomalies:
        st.warning("⚠️ Relay Anomalies Detected:")
        for anomaly in anomalies:
            sev_icon = "🔴" if anomaly.get('severity') == 'high' else "🟠"
            st.text(f"{sev_icon} {anomaly.get('message', '')}")


# ── Render: Threat Indicators ────────────────────────────────────────────────

def render_threat_indicators(result):
    section_header("🚨", "Threat Indicators")

    indicators = result.get('threat_indicators', {})

    col1, col2 = st.columns(2)

    with col1:
        # Lookalike domain
        lookalike = indicators.get('lookalike_domain', {})
        if lookalike.get('is_lookalike'):
            st.markdown(
                f'<div class="indicator-row danger">'
                f'<div><span style="color:#f85149;font-weight:700;">🚨 Lookalike Domain</span><br>'
                f'<span class="indicator-value">{lookalike.get("example", "")}</span></div></div>',
                unsafe_allow_html=True,
            )
        elif lookalike.get('suspicious_tld'):
            st.markdown(
                f'<div class="indicator-row warning">'
                f'<div><span style="color:#d29922;font-weight:700;">⚠ Suspicious TLD</span><br>'
                f'<span class="indicator-value">{lookalike.get("tld", "")}</span></div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="indicator-row safe">'
                '<div><span style="color:#00ff41;font-weight:700;">✓ No Lookalike Domain</span></div></div>',
                unsafe_allow_html=True,
            )

        # Sender mismatch
        sender_mismatch = indicators.get('sender_mismatch', {})
        if sender_mismatch.get('mismatch'):
            st.markdown(
                f'<div class="indicator-row danger">'
                f'<div><span style="color:#f85149;font-weight:700;">🚨 Sender Mismatch</span><br>'
                f'<span class="indicator-label">Header:</span> '
                f'<span class="indicator-value">{sender_mismatch.get("header_domain")}</span><br>'
                f'<span class="indicator-label">Envelope:</span> '
                f'<span class="indicator-value">{sender_mismatch.get("envelope_domain")}</span>'
                f'</div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="indicator-row safe">'
                '<div><span style="color:#00ff41;font-weight:700;">✓ No Sender Mismatch</span></div></div>',
                unsafe_allow_html=True,
            )

        # Urgency keywords
        urgency = indicators.get('urgency_keywords', [])
        if urgency:
            kw_list = ', '.join(urgency[:5])
            st.markdown(
                f'<div class="indicator-row danger">'
                f'<div><span style="color:#f85149;font-weight:700;">🚨 Urgency Keywords ({len(urgency)})</span><br>'
                f'<span class="indicator-value" style="font-size:0.9rem;">{kw_list}</span></div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="indicator-row safe">'
                '<div><span style="color:#00ff41;font-weight:700;">✓ No Urgency Keywords</span></div></div>',
                unsafe_allow_html=True,
            )

    with col2:
        # Link mismatches
        link_mismatches = indicators.get('link_mismatches', [])
        if link_mismatches:
            items_html = ''.join(
                f'<span class="indicator-label">• {m.get("visible_text", "N/A")[:30]}</span> → '
                f'<span class="indicator-value">{m.get("actual_domain", "N/A")}</span><br>'
                for m in link_mismatches[:3]
            )
            st.markdown(
                f'<div class="indicator-row danger">'
                f'<div><span style="color:#f85149;font-weight:700;">🚨 Link Mismatches ({len(link_mismatches)})</span><br>'
                f'{items_html}</div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="indicator-row safe">'
                '<div><span style="color:#00ff41;font-weight:700;">✓ No Link Mismatches</span></div></div>',
                unsafe_allow_html=True,
            )

        # Suspicious URLs
        suspicious_urls = indicators.get('suspicious_urls', [])
        if suspicious_urls:
            url_html = ''.join(
                f'<span class="indicator-value">{u.get("domain", "N/A")}</span>'
                f'<span class="indicator-label"> — {", ".join(u.get("reasons", [])[:2])}</span><br>'
                for u in suspicious_urls[:3]
            )
            st.markdown(
                f'<div class="indicator-row danger">'
                f'<div><span style="color:#f85149;font-weight:700;">🚨 Suspicious URLs ({len(suspicious_urls)})</span><br>'
                f'{url_html}</div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="indicator-row safe">'
                '<div><span style="color:#00ff41;font-weight:700;">✓ No Suspicious URLs</span></div></div>',
                unsafe_allow_html=True,
            )

        # Domain age
        domain_info = result.get('domain_info', {})
        if domain_info.get('is_new'):
            st.markdown(
                f'<div class="indicator-row danger">'
                f'<div><span style="color:#f85149;font-weight:700;">🚨 New Domain</span><br>'
                f'<span class="indicator-value">{domain_info.get("age_days", 0)} days old</span></div></div>',
                unsafe_allow_html=True,
            )
        else:
            age = domain_info.get('age_days', 'Unknown')
            st.markdown(
                f'<div class="indicator-row safe">'
                f'<div><span style="color:#00ff41;font-weight:700;">✓ Domain Age OK</span><br>'
                f'<span class="indicator-label">{age} days</span></div></div>',
                unsafe_allow_html=True,
            )


# ── Render: Scoring Breakdown ────────────────────────────────────────────────

def render_scoring_breakdown(result):
    section_header("📊", "Scoring Breakdown")

    reasons = result.get('scoring_reasons', [])
    if not reasons:
        st.info("No scoring details available")
        return

    cols = st.columns(2)
    for i, reason in enumerate(reasons):
        col = cols[i % 2]
        if '+' in reason:
            col.markdown(
                f'<div style="background:#f8514908;border:1px solid #f8514920;border-radius:8px;'
                f'padding:8px 14px;margin-bottom:6px;color:#f85149;font-size:0.9rem;">'
                f'▲ {reason}</div>',
                unsafe_allow_html=True,
            )
        elif 'discount' in reason.lower():
            col.markdown(
                f'<div style="background:#00ff4108;border:1px solid #00ff4120;border-radius:8px;'
                f'padding:8px 14px;margin-bottom:6px;color:#00ff41;font-size:0.9rem;">'
                f'▼ {reason}</div>',
                unsafe_allow_html=True,
            )
        else:
            col.markdown(
                f'<div style="background:#8b949e08;border:1px solid #30363d;border-radius:8px;'
                f'padding:8px 14px;margin-bottom:6px;color:#8b949e;font-size:0.9rem;">'
                f'● {reason}</div>',
                unsafe_allow_html=True,
            )


# ── Render: Export Options ───────────────────────────────────────────────────

def render_export_options(result):
    section_header("📄", "Export Report")

    col1, col2 = st.columns(2)

    with col1:
        json_report = json.dumps(result, indent=2, default=str)
        st.download_button(
            label="📥 Download JSON Report",
            data=json_report,
            file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col2:
        text_report = st.session_state.analyzer.generate_report(result, format='text')
        st.download_button(
            label="📥 Download Text Report",
            data=text_report,
            file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True,
        )


# ── Render: Welcome Screen ──────────────────────────────────────────────────

def render_welcome_screen():
    # Hero
    st.markdown("""
    <div class="welcome-hero">
        <h1>🛡️ PhishGuard</h1>
        <p>Advanced Email Security &amp; Phishing Detection Platform.<br>
        Reduce manual SOC analysis from 10 minutes to 10 seconds.</p>
    </div>
    """, unsafe_allow_html=True)

    # Feature grid — DOTDNA inspired numbered cards
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-num">[ 01 ]</div>
            <h4>🔐 Authentication Analysis</h4>
            <p>SPF, DKIM, and DMARC validation to verify email
            authenticity and detect spoofed senders.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <div class="feature-num">[ 02 ]</div>
            <h4>🌍 Relay Path Tracing</h4>
            <p>Trace the email's journey through mail servers
            with IP geolocation and anomaly detection.</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-num">[ 03 ]</div>
            <h4>🧠 Threat Intelligence</h4>
            <p>IP reputation scoring, domain age analysis,
            and URL reputation checks against threat databases.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <div class="feature-num">[ 04 ]</div>
            <h4>👤 Lookalike Domains</h4>
            <p>DNS-verified lookalike detection using Levenshtein distance
            against 106+ brand domains including Indian banks.</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-num">[ 05 ]</div>
            <h4>🔗 Link Analysis</h4>
            <p>Find mismatched URLs where visible text differs
            from actual destination — a top phishing indicator.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <div class="feature-num">[ 06 ]</div>
            <h4>⏰ Urgency Detection</h4>
            <p>Identify social engineering pressure tactics
            commonly used in phishing campaigns.</p>
        </div>
        """, unsafe_allow_html=True)

    # Getting started
    st.markdown("---")
    st.markdown("""
    <div style="text-align:center;padding:20px 0;">
        <p style="color:#c9d1d9;font-size:1.15rem;font-weight:600;margin-bottom:8px;">
            Get Started
        </p>
        <p style="color:#8b949e;font-size:0.95rem;max-width:500px;margin:0 auto;line-height:1.6;">
            Upload an <code>.eml</code> file, paste raw email headers, or
            try the built-in sample — use the sidebar to begin.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Session stats
    if st.session_state.analysis_history:
        st.markdown("---")
        section_header("📈", "Session Statistics")

        stats = st.session_state.analyzer.get_statistics()

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(
                f'<div class="metric-card"><div class="stat-num">{stats["total_analyzed"]}</div>'
                f'<div class="stat-label">Total Analyzed</div></div>',
                unsafe_allow_html=True,
            )
        with c2:
            st.markdown(
                f'<div class="metric-card"><div class="stat-num" style="color:#f85149;">'
                f'{stats["high_risk"]}</div><div class="stat-label">High Risk</div></div>',
                unsafe_allow_html=True,
            )
        with c3:
            st.markdown(
                f'<div class="metric-card"><div class="stat-num" style="color:#d29922;">'
                f'{stats["medium_risk"]}</div><div class="stat-label">Medium Risk</div></div>',
                unsafe_allow_html=True,
            )
        with c4:
            st.markdown(
                f'<div class="metric-card"><div class="stat-num">{stats["avg_time"]}s</div>'
                f'<div class="stat-label">Avg Time</div></div>',
                unsafe_allow_html=True,
            )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    render_header()
    render_sidebar()

    if st.session_state.analysis_result:
        result = st.session_state.analysis_result

        render_threat_score(result)
        st.divider()
        render_email_metadata(result)
        st.divider()
        render_authentication_results(result)
        st.divider()
        render_relay_path(result)
        st.divider()
        render_threat_indicators(result)
        st.divider()
        render_scoring_breakdown(result)
        st.divider()
        render_export_options(result)
    else:
        render_welcome_screen()


if __name__ == "__main__":
    main()
