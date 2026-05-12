"""
theme.py — CSS constants and the injected stylesheet.
Everything the agent UI needs to look like a modern SOC platform.
"""

DARK_CSS = """
<style>
/* ── Google Font ───────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Global reset ──────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

/* ── App background ────────────────────────────────────── */
.stApp {
    background: #0d1117;
    color: #e6edf3;
}

/* ── Sidebar ───────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: #161b22;
    border-right: 1px solid #30363d;
}

[data-testid="stSidebar"] .stMarkdown h1,
[data-testid="stSidebar"] .stMarkdown h2,
[data-testid="stSidebar"] .stMarkdown h3 {
    color: #58a6ff;
}

/* ── Hide default Streamlit branding ───────────────────── */
#MainMenu { visibility: hidden; }
footer     { visibility: hidden; }
header     { visibility: hidden; }

/* ── Chat container ────────────────────────────────────── */
.chat-container {
    max-width: 860px;
    margin: 0 auto;
    padding: 0 1rem 6rem 1rem;
}

/* ── Message bubbles ───────────────────────────────────── */
.msg-user {
    display: flex;
    justify-content: flex-end;
    margin: 0.75rem 0;
    animation: fadeIn 0.2s ease;
}

.msg-user .bubble {
    background: #1f6feb;
    color: #ffffff;
    border-radius: 18px 18px 4px 18px;
    padding: 0.65rem 1rem;
    max-width: 72%;
    font-size: 0.92rem;
    line-height: 1.55;
    word-break: break-word;
}

.msg-agent {
    display: flex;
    justify-content: flex-start;
    align-items: flex-start;
    gap: 0.6rem;
    margin: 0.75rem 0;
    animation: fadeIn 0.2s ease;
}

.msg-agent .avatar {
    width: 32px;
    height: 32px;
    min-width: 32px;
    background: linear-gradient(135deg, #1f6feb 0%, #58a6ff 100%);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 700;
    color: white;
    margin-top: 2px;
}

.msg-agent .bubble {
    background: #161b22;
    border: 1px solid #30363d;
    color: #e6edf3;
    border-radius: 4px 18px 18px 18px;
    padding: 0.75rem 1rem;
    max-width: 82%;
    font-size: 0.92rem;
    line-height: 1.6;
    word-break: break-word;
}

/* ── Tables inside bubbles ─────────────────────────────── */
.msg-agent .bubble table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.6rem 0;
    font-size: 0.84rem;
    font-family: 'JetBrains Mono', monospace;
}

.msg-agent .bubble table th {
    background: #21262d;
    color: #58a6ff;
    padding: 0.4rem 0.75rem;
    text-align: left;
    border-bottom: 1px solid #30363d;
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.msg-agent .bubble table td {
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid #21262d;
    color: #c9d1d9;
}

.msg-agent .bubble table tr:hover td {
    background: #1c2128;
}

/* ── Confirmation card ─────────────────────────────────── */
.confirm-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-left: 4px solid #d29922;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin: 0.5rem 0;
    max-width: 640px;
}

.confirm-card.danger {
    border-left-color: #f85149;
}

.confirm-card .confirm-title {
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #d29922;
    margin-bottom: 0.5rem;
}

.confirm-card.danger .confirm-title {
    color: #f85149;
}

.confirm-card .confirm-body {
    font-size: 0.88rem;
    color: #c9d1d9;
    line-height: 1.65;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Security findings ─────────────────────────────────── */
.finding-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin: 0.5rem 0;
}

.finding-card.critical { border-left: 4px solid #f85149; }
.finding-card.high     { border-left: 4px solid #e3b341; }
.finding-card.medium   { border-left: 4px solid #d29922; }
.finding-card.low      { border-left: 4px solid #3fb950; }
.finding-card.info     { border-left: 4px solid #58a6ff; }

.severity-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.4rem;
}

.severity-badge.critical { background: rgba(248,81,73,0.2);  color: #f85149; }
.severity-badge.high     { background: rgba(227,179,65,0.2); color: #e3b341; }
.severity-badge.medium   { background: rgba(210,153,34,0.2); color: #d29922; }
.severity-badge.low      { background: rgba(63,185,80,0.2);  color: #3fb950; }
.severity-badge.info     { background: rgba(88,166,255,0.2); color: #58a6ff; }

/* ── Status indicators ─────────────────────────────────── */
.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
    vertical-align: middle;
}

.status-dot.connected    { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
.status-dot.disconnected { background: #f85149; }
.status-dot.pending      { background: #d29922; animation: pulse 1.2s infinite; }

/* ── Verified / error badges ───────────────────────────── */
.badge-verified { color: #3fb950; font-size: 0.82rem; font-weight: 600; }
.badge-failed   { color: #f85149; font-size: 0.82rem; font-weight: 600; }
.badge-warning  { color: #d29922; font-size: 0.82rem; font-weight: 600; }

/* ── Input area ────────────────────────────────────────── */
.stChatInput > div {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 12px !important;
}

.stChatInput textarea {
    color: #e6edf3 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.92rem !important;
}

/* ── Buttons ───────────────────────────────────────────── */
.stButton > button {
    border-radius: 8px;
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    font-size: 0.88rem;
    transition: all 0.15s ease;
    border: none;
}

.btn-confirm > button {
    background: #1f6feb !important;
    color: #ffffff !important;
    padding: 0.5rem 1.5rem !important;
}

.btn-confirm > button:hover {
    background: #388bfd !important;
}

.btn-cancel > button {
    background: #21262d !important;
    color: #8b949e !important;
    border: 1px solid #30363d !important;
}

.btn-cancel > button:hover {
    background: #30363d !important;
    color: #e6edf3 !important;
}

.btn-danger > button {
    background: rgba(248,81,73,0.15) !important;
    color: #f85149 !important;
    border: 1px solid rgba(248,81,73,0.4) !important;
}

/* ── Dividers ──────────────────────────────────────────── */
hr {
    border-color: #21262d !important;
    margin: 0.75rem 0 !important;
}

/* ── Code blocks ───────────────────────────────────────── */
code, pre {
    font-family: 'JetBrains Mono', monospace !important;
    background: #0d1117 !important;
    color: #79c0ff !important;
    border: 1px solid #21262d !important;
    border-radius: 6px !important;
    font-size: 0.82rem !important;
}

/* ── Scrollbar ─────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

/* ── Animations ────────────────────────────────────────── */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
}

/* ── Metric cards ──────────────────────────────────────── */
[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.75rem 1rem;
}

/* ── Expanders ─────────────────────────────────────────── */
[data-testid="stExpander"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
}
</style>
"""