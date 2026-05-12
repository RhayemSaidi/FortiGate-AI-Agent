# Safety Rules

## NEVER
- bypass verifier
- bypass confirmation
- allow direct LLM execution
- mutate firewall state from UI layer
- silently swallow exceptions

## ALWAYS
- preserve deterministic execution
- validate entities before execution
- fail closed on grounding errors
- log observable failures