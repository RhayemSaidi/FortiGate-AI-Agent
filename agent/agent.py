"""
agent.py — CLI interface for the FortiGate AI Agent.

All logic lives in core.py (AgentSession).
This file handles terminal I/O only.

Updated to work with the new AgentResponse return type from AgentSession.process().
"""

import sys
import os

# ── Path setup — must happen before any local imports ────────────────────────
_AGENT_DIR  = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR   = os.path.dirname(_AGENT_DIR)
sys.path.insert(0, _ROOT_DIR)   # project root — for config, modules, audit
sys.path.insert(0, _AGENT_DIR)  # agent dir — for core, tools, prompt, etc.

from core import AgentSession, ResponseKind


def run_cli():
    session = AgentSession()

    print("\n" + "=" * 55)
    print("  FortiGate AI Agent")
    print("  Powered by Mistral AI + FortiOS Knowledge Base")
    print("=" * 55)
    print("Type 'exit' to quit.\n")

    while True:
        # Show a different prompt when waiting for confirmation
        prompt = "You (yes/no): " if session.has_pending else "You: "

        try:
            user_input = input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
            break

        if user_input.lower() in ("exit", "quit"):
            print("Goodbye!")
            break

        if not user_input:
            continue

        try:
            response = session.process(user_input)
        except Exception as exc:
            # Should not reach here — AgentSession.process() wraps all errors
            print(f"\nUnexpected error: {exc}\n")
            continue

        # Print the response text
        if response.text:
            print(f"\nAgent: {response.text}\n")

        # Indicate if we are in a confirmation state
        # (the prompt changes on next iteration)


if __name__ == "__main__":
    run_cli()