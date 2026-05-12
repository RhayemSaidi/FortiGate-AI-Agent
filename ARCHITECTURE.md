# FortiGate AI Agent Architecture

## Core Principle
LLM interprets only.
Execution is deterministic.

## Write Pipeline
NLU → Grounding → Validation → Confirmation → Executor → Verifier

## Safety Invariants
- LLM never executes firewall changes directly
- Executor is sole write authority
- Verifier confirms final appliance state
- Frontend cannot bypass backend safety checks

## Major Modules

### core.py
Main orchestration engine.

### nlu_interpreter.py
Mistral-based structured intent extraction.

### nlu_grounder.py
Validates entities against live FortiGate state.

### executor.py
Applies policy updates through verified PUT flow.

### verifier.py
Confirms resulting firewall state.

## Migration State
Hybrid migration:
- legacy regex routing still partially active
- NLU layer partially integrated