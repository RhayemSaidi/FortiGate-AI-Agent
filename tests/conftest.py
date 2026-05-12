"""
conftest.py — pytest configuration and path setup.

Establishes sys.path so that all agent modules, config, and modules/
are importable from test files regardless of pytest working directory.
"""

import sys
import os

# Project root (contains config.py, modules/, audit/)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Agent directory (contains core.py, tools.py, nlu_*, etc.)
_AGENT = os.path.join(_ROOT, "agent")

# Insert at front to override any stale system paths
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if _AGENT not in sys.path:
    sys.path.insert(0, _AGENT)