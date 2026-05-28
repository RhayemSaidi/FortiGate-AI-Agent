"""
theme.py — Minimal monochrome dark theme.
Philosophy: flat, calm, readable. No gradients, no glows, no JS hacks.
"""

DARK_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&family=JetBrains+Mono:wght@300;400&display=swap');

/* ── Reset & base ─────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
    -webkit-font-smoothing: antialiased;
}

.stApp {
    background: #080808;
    color: #eeeeee;
}

/* ── Sidebar ─────────────────────────────────── */
/* Force Streamlit header icons to be white so they are visible on black background */
[data-testid="collapsedControl"] svg,
[data-testid="stHeader"] svg {
    fill: #ffffff !important;
    color: #ffffff !important;
}

[data-testid="collapsedControl"]:hover svg,
[data-testid="stHeader"] button:hover svg {
    fill: #aaaaaa !important;
    color: #aaaaaa !important;
}

[data-testid="stSidebar"] {
    background-color: #0a0a0a !important;
    border-right: 1px solid #1a1a1a !important;
}

/* ── Sidebar: primary action buttons */
[data-testid="stSidebar"] .stButton > button {
    background: transparent !important;
    border: 1px solid #2a2a2a !important;
    color: #888888 !important;
    border-radius: 2px !important;
    font-size: 0.75rem !important;
    font-weight: 400 !important;
    letter-spacing: 0.03em !important;
    padding: 0.45rem 0.8rem !important;
    text-align: left !important;
    width: 100% !important;
    transition: border-color 0.15s ease, color 0.15s ease !important;
}

[data-testid="stSidebar"] .stButton > button:hover {
    border-color: #cccccc !important;
    color: #eeeeee !important;
    background: #111111 !important;
}

/* ── Sidebar: quick command buttons */
[data-testid="stSidebar"] .stButton > button p {
    font-size: 0.75rem !important;
}

[data-testid="stSidebar"] hr {
    border-color: #1a1a1a !important;
    margin: 0.8rem 0 !important;
}

/* ── Fix Streamlit bottom bar & structural containers ─────── */
[data-testid="stBottom"],
[data-testid="stBottom"] > div,
[data-testid="stBottomBlockContainer"],
[data-testid="stAppViewBlockContainer"],
[data-testid="stHeader"],
[data-testid="stVerticalBlock"],
[data-testid="stChatInputContainer"] {
    background: transparent !important;
    background-color: transparent !important;
}

[data-testid="stBottom"] {
    border-top: 1px solid #1a1a1a !important;
}

/* Fallback: any sticky-positioned div should also match */
div[style*="position: sticky"],
div[style*="position:sticky"],
div[style*="position: fixed"],
div[style*="position:fixed"] {
    background-color: transparent !important;
}

/* ── Chat messages ────────────────────────────── */
.msg-user {
    display: flex;
    justify-content: flex-end;
    margin: 1.5rem 0;
}

.msg-user .bubble {
    background: #ffffff;
    color: #000000;
    border-radius: 4px;
    padding: 0.8rem 1.2rem;
    max-width: 70%;
    font-size: 0.95rem;
    line-height: 1.5;
    word-break: break-word;
    font-weight: 500;
}

.msg-agent {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    margin: 1.5rem 0;
}

.agent-icon {
    width: 24px;
    height: 24px;
    min-width: 24px;
    background: #000000;
    border: 1px solid #333333;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.65rem;
    font-weight: 600;
    color: #ffffff;
    margin-top: 4px;
    flex-shrink: 0;
}

.msg-agent .bubble {
    background: transparent;
    color: #dddddd;
    padding: 0.2rem 0;
    max-width: 85%;
    font-size: 0.95rem;
    line-height: 1.6;
    word-break: break-word;
    font-weight: 300;
}

/* ── Fix Streamlit Input ───────────────────────── */
[data-testid="stChatInput"] {
    background-color: #0d0d0d !important;
    border: 1px solid #333333 !important;
    border-radius: 4px !important;
}
[data-testid="stChatInput"]:focus-within {
    border-color: #ffffff !important;
}
[data-testid="stChatInput"] textarea {
    color: #ffffff !important;
    background-color: transparent !important;
    font-weight: 400 !important;
}

/* ── Fix Streamlit bottom bar (grey block under input) ── */
[data-testid="stBottom"] {
    background: #080808 !important;
    border-top: 1px solid #1a1a1a !important;
    padding-top: 0.5rem !important;
}

[data-testid="stBottom"] > div {
    background: #080808 !important;
}

[data-testid="stChatInputContainer"] {
    background: #080808 !important;
    padding: 0.25rem 0 !important;
}

.stChatInput {
    background: #080808 !important;
}

/* Remove any Streamlit default white/grey backgrounds */
[data-testid="stAppViewContainer"] {
    background: #080808 !important;
}

[data-testid="stVerticalBlock"] {
    background: transparent !important;
}

/* ── Monospace output block ───────────────────── */
.mono-out {
    background: #0a0a0a;
    border: 1px solid #222222;
    padding: 0.8rem 1rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #cccccc;
    line-height: 1.6;
    overflow-x: auto;
    white-space: pre;
    margin: 0.5rem 0;
}

/* ── Policy table ─────────────────────────────── */
.policy-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    margin: 0.5rem 0;
    border: 1px solid #222222;
}

.policy-table th {
    background: #0a0a0a;
    color: #ffffff;
    padding: 0.5rem 0.8rem;
    text-align: left;
    border-bottom: 1px solid #333333;
    font-weight: 400;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.policy-table td {
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid #1a1a1a;
    color: #bbbbbb;
    font-weight: 300;
}

.policy-table tr:hover td { background: #111111; color: #ffffff; }

.c-accept  { color: #ffffff; font-weight: 500; }
.c-deny    { color: #777777; text-decoration: line-through; }
.c-enabled { color: #ffffff; }
.c-disabled{ color: #555555; }

/* ── Confirmation card ────────────────────────── */
.confirm-card {
    background: #080808;
    border: 1px solid #333333;
    padding: 1rem 1.2rem;
    max-width: 560px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    color: #dddddd;
    line-height: 1.6;
}

.confirm-card.danger {
    border-color: #ffffff;
}

.confirm-label {
    font-size: 0.7rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #ffffff;
    margin-bottom: 0.8rem;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid #222222;
}

/* ── Inline status tags ───────────────────────── */
.tag {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    font-size: 0.7rem;
    font-weight: 400;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border: 1px solid;
    background: #000000;
}

.tag.ok   { border-color: #ffffff; color: #ffffff; }
.tag.err  { border-color: #777777; color: #dddddd; background: #1a1a1a; }
.tag.warn { border-color: #555555; color: #cccccc; }
.tag.info { border-color: #333333; color: #aaaaaa; }

/* ── Notice strip ─────────────────────────────── */
.notice {
    font-size: 0.85rem;
    padding: 0.6rem 0.8rem;
    border: 1px solid #222222;
    background: #0a0a0a;
    color: #cccccc;
    margin: 0.5rem 0;
    line-height: 1.5;
    font-weight: 300;
}

/* ── Buttons ──────────────────────────────────── */
.stButton > button {
    border-radius: 2px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 400 !important;
    font-size: 0.85rem !important;
    transition: all 0.2s ease !important;
}

.btn-ok .stButton > button {
    background: #ffffff !important;
    border: 1px solid #ffffff !important;
    color: #000000 !important;
    padding: 0.5rem 1.2rem !important;
}
.btn-ok .stButton > button:hover {
    background: #dddddd !important;
    border-color: #dddddd !important;
}

.btn-cancel .stButton > button {
    background: transparent !important;
    border: 1px solid #555555 !important;
    color: #cccccc !important;
    padding: 0.5rem 1.2rem !important;
}
.btn-cancel .stButton > button:hover {
    border-color: #ffffff !important;
    color: #ffffff !important;
}

.btn-danger .stButton > button {
    background: transparent !important;
    border: 1px solid #ffffff !important;
    color: #ffffff !important;
    padding: 0.5rem 1.2rem !important;
}
.btn-danger .stButton > button:hover {
    background: #ffffff !important;
    color: #000000 !important;
}

/* ── Inline code ──────────────────────────────── */
code {
    font-family: 'JetBrains Mono', monospace !important;
    background: #111111 !important;
    color: #ffffff !important;
    border: 1px solid #333333 !important;
    border-radius: 2px !important;
    padding: 0.15em 0.4em !important;
    font-size: 0.85em !important;
}

/* ── Scrollbar ────────────────────────────────── */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #333333; }

/* ── Metrics ──────────────────────────────────── */
[data-testid="metric-container"] {
    background: #0a0a0a !important;
    border: 1px solid #222222 !important;
    padding: 0.8rem 1rem !important;
}
[data-testid="stMetricValue"] { color: #ffffff !important; font-size: 1.2rem !important; font-weight: 400 !important; }
[data-testid="stMetricLabel"] { color: #888888 !important; font-size: 0.75rem !important; font-weight: 300 !important; text-transform: uppercase; letter-spacing: 0.05em; }

/* ── Thinking dots ────────────────────────────── */
@keyframes blink { 0%,100%{opacity:0.2} 50%{opacity:1} }
.dot1{animation:blink 1.2s infinite}
.dot2{animation:blink 1.2s 0.2s infinite}
.dot3{animation:blink 1.2s 0.4s infinite}
</style>
"""