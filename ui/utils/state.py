"""
state.py — Streamlit session state management.
"""
from __future__ import annotations

import sys
import os
from typing import Optional

import streamlit as st

_UI_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT_DIR  = os.path.dirname(_UI_DIR)
_AGENT_DIR = os.path.join(_ROOT_DIR, "agent")
for p in (_ROOT_DIR, _AGENT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)


def init_state() -> None:
    defaults = {
        "agent":        None,
        "messages":     [],
        "pending":      False,
        "pending_text": "",
        "fg_connected": None,
        "fg_info":      {},       # hostname, version, uptime, serial
        "fg_resources": {},       # cpu, memory (refreshed on demand)
        "fg_counts":    {},       # policy_count, interface_count
        "last_action":  "",       # last executed operation label
        "input_key":    0,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


def get_agent():
    if st.session_state.agent is None:
        from core import AgentSession
        st.session_state.agent = AgentSession()
    return st.session_state.agent


def push_message(role: str, content: str, kind: str = "answer", meta: dict = None) -> None:
    st.session_state.messages.append({
        "role":    role,
        "content": content,
        "kind":    kind,
        "meta":    meta or {},
    })


def check_fortigate_connection() -> bool:
    """
    Full connectivity check — fetches system info, resources, and counts.
    Updates fg_connected, fg_info, fg_resources, fg_counts.
    """
    try:
        from modules.system import get_system_status
        r = get_system_status()
        if not isinstance(r, dict):
            r = {}
        
        # FortiGate returns system status inside 'results'
        results = r.get("results", r)

        st.session_state.fg_connected = True
        st.session_state.fg_info = {
            "hostname": results.get("hostname", "FortiGate"),
            "version":  r.get("version") or results.get("version", ""),
            "serial":   r.get("serial") or results.get("serial", "N/A"),
            "model":    results.get("model_name") or results.get("model", ""),
            "uptime":   _format_uptime(results.get("uptime", r.get("uptime", 0))) or "N/A",
        }

        # Best-effort: fetch resources and counts (non-fatal if unavailable)
        _fetch_resources()
        _fetch_counts()
        return True

    except Exception:
        st.session_state.fg_connected = False
        st.session_state.fg_info      = {}
        st.session_state.fg_resources = {}
        st.session_state.fg_counts    = {}
        return False


def _fetch_resources() -> None:
    try:
        from modules.system import get_system_performance
        raw = get_system_performance()
        if isinstance(raw, dict):
            results = raw.get("results", raw)
            if isinstance(results, dict):
                # CPU parsing
                cpu_raw = results.get("cpu", {})
                if isinstance(cpu_raw, dict) and "idle" in cpu_raw:
                    cpu_val = max(0, 100 - float(cpu_raw["idle"]))
                elif isinstance(cpu_raw, list) and len(cpu_raw) > 0 and isinstance(cpu_raw[0], dict) and "idle" in cpu_raw[0]:
                    cpu_val = max(0, 100 - float(cpu_raw[0]["idle"]))
                elif isinstance(cpu_raw, (int, float)):
                    cpu_val = cpu_raw
                else:
                    cpu_val = None

                # Memory parsing
                mem_raw = results.get("mem", results.get("memory", {}))
                if isinstance(mem_raw, dict) and "total" in mem_raw and "used" in mem_raw and float(mem_raw["total"]) > 0:
                    mem_val = (float(mem_raw["used"]) / float(mem_raw["total"])) * 100
                elif isinstance(mem_raw, list) and len(mem_raw) > 0 and isinstance(mem_raw[0], dict) and "total" in mem_raw[0]:
                    m = mem_raw[0]
                    mem_val = (float(m["used"]) / float(m["total"])) * 100 if float(m["total"]) > 0 else None
                elif isinstance(mem_raw, (int, float)):
                    mem_val = mem_raw
                else:
                    mem_val = None

                st.session_state.fg_resources = {
                    "cpu":    int(cpu_val) if cpu_val is not None else None,
                    "memory": int(mem_val) if mem_val is not None else None,
                }
                return
    except Exception:
        pass
    st.session_state.fg_resources = {}



def _fetch_counts() -> None:
    try:
        from modules.policies import list_policies
        r       = list_policies()
        results = r if isinstance(r, list) else r.get("results", [])
        policy_count = len(results)
    except Exception:
        policy_count = None

    try:
        from modules.interfaces import list_interfaces
        r       = list_interfaces()
        results = r if isinstance(r, list) else r.get("results", [])
        iface_count = len(results)
    except Exception:
        iface_count = None

    st.session_state.fg_counts = {
        "policies":   policy_count,
        "interfaces": iface_count,
    }


def _format_uptime(seconds: int) -> str:
    if not seconds or not isinstance(seconds, (int, float)):
        return ""
    s = int(seconds)
    d = s // 86400
    h = (s % 86400) // 3600
    m = (s % 3600) // 60
    if d > 0:
        return f"{d}d {h}h {m}m"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"