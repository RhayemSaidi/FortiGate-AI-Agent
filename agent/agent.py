import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from tools import ALL_TOOLS
from prompt import SYSTEM_PROMPT

# Import audit logger
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from audit.logger import log_action, log_conversation


def build_agent():
    llm = ChatOllama(
        model="qwen2.5:3b",
        temperature=0,
    ).bind_tools(ALL_TOOLS)
    return llm


def run_cli():
    llm = build_agent()
    messages = [SystemMessage(content=SYSTEM_PROMPT)]

    print("\n" + "="*50)
    print("  FortiGate AI Agent - Terminal Mode")
    print("="*50)
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() in ["exit", "quit"]:
            print("Goodbye!")
            break
        if not user_input:
            continue

        try:
            messages.append(HumanMessage(content=user_input))
            response = llm.invoke(messages)
            messages.append(response)

            if response.tool_calls:
                for tool_call in response.tool_calls:
                    tool_name = tool_call["name"]
                    tool_input = tool_call["args"].get("input", "")

                    tool = next((t for t in ALL_TOOLS if t.name == tool_name), None)
                    if tool:
                        print(f"\n[Calling tool: {tool_name}]")
                        tool_result = tool.invoke(tool_input)
                        print(f"[Tool result: {tool_result}]")

                        # ── AUDIT LOG ──────────────────────────────
                        log_action(
                            action=tool_name.upper(),
                            user_input=user_input,
                            tool_called=tool_name,
                            tool_input=str(tool_input),
                            result=str(tool_result),
                            status="success" if "error" not in str(tool_result).lower() else "error"
                        )
                        # ───────────────────────────────────────────

                        messages.append(ToolMessage(
                            content=str(tool_result),
                            tool_call_id=tool_call["id"]
                        ))

                final_response = llm.invoke(messages)
                messages.append(final_response)
                print(f"\nAgent: {final_response.content}\n")

                # Log the conversation turn
                log_conversation(user_input, final_response.content)

            else:
                print(f"\nAgent: {response.content}\n")
                log_conversation(user_input, response.content)

        except Exception as e:
            print(f"\nError: {str(e)}\n")
            log_action(
                action="UNKNOWN",
                user_input=user_input,
                tool_called="none",
                tool_input="",
                result=str(e),
                status="error"
            )


if __name__ == "__main__":
    run_cli()