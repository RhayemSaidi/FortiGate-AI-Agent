"""
agent.py — CLI interface for the FortiGate AI Agent.

All logic lives in core.py (AgentSession).
This file handles terminal I/O only.
"""

import sys
import os

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

# ── Path setup — must happen before any local imports ────────────────────────
_AGENT_DIR  = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR   = os.path.dirname(_AGENT_DIR)
sys.path.insert(0, _ROOT_DIR)
sys.path.insert(0, _AGENT_DIR)

from core import AgentSession, ResponseKind


def _print_response(console: Console, response) -> None:
    """Route each ResponseKind to an appropriate Rich renderer."""
    text = response.text.strip()
    kind = response.kind

    if not text:
        return

    if kind == ResponseKind.CONFIRMATION:
        # Check which sub-type it is
        is_warning = "VALIDATION WARNING" in text.upper()
        border  = "yellow" if is_warning else "cyan"
        title   = "⚠  Validation Warning" if is_warning else "Confirmation Required"

        # Strip the heading line and the separator line so we don't double-render
        cleaned_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped in ("CONFIRMATION REQUIRED", "VALIDATION WARNING",
                            "CONFIRMATION REQUIRED (MULTI-POLICY)",
                            "CONFIRMATION REQUIRED (MULTI-POLICY DELETE)"):
                continue
            if set(stripped) <= {"─", "=", "-"} and len(stripped) > 4:
                continue
            cleaned_lines.append(line)

        body = Text.from_markup("\n".join(cleaned_lines).strip())
        console.print()
        console.print(Panel(body, title=f"[bold {border}]{title}[/bold {border}]",
                            border_style=border, padding=(0, 2)))

    elif kind == ResponseKind.BLOCKED:
        console.print()
        console.print(Panel(
            Text(text, style="red"),
            title="[bold red]Blocked[/bold red]",
            border_style="red", padding=(0, 2)
        ))

    elif kind == ResponseKind.CANCELLED:
        console.print()
        console.print(f"[dim]  Cancelled.[/dim]")

    elif kind == ResponseKind.ERROR:
        console.print()
        console.print(Panel(
            Text(text, style="red"),
            title="[bold red]Error[/bold red]",
            border_style="red", padding=(0, 2)
        ))

    elif kind == ResponseKind.WARNING:
        console.print()
        console.print(Panel(
            Text(text, style="yellow"),
            title="[bold yellow]Warning[/bold yellow]",
            border_style="yellow", padding=(0, 2)
        ))

    else:
        # ANSWER — plain Markdown
        console.print()
        console.print(Markdown(text))


def run_cli():
    session = AgentSession()
    console = Console()

    console.print()
    console.print(Panel(
        "[bold white]FortiGate AI Agent[/bold white]\n"
        "[dim]Powered by Mistral AI + FortiOS Knowledge Base[/dim]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print("[dim]  Type 'exit' to quit.[/dim]\n")

    while True:
        prompt = (
            "\n[bold green]You (yes/no):[/bold green] "
            if session.has_pending
            else "\n[bold green]You:[/bold green] "
        )

        try:
            user_input = console.input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if user_input.lower() in ("exit", "quit"):
            console.print("[dim]Goodbye.[/dim]")
            break

        if not user_input:
            continue

        try:
            response = session.process(user_input)
        except Exception as exc:
            console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}\n")
            continue

        console.print("\n[bold cyan]Agent:[/bold cyan]")
        _print_response(console, response)
        console.print()


if __name__ == "__main__":
    run_cli()
