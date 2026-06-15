"""
agent_errors.py — Structured exception hierarchy for the agent.
"""


class AgentError(Exception):
    """Base class for all agent errors."""
    pass


class NLUError(AgentError):
    """Errors in the NLU interpretation layer."""
    pass


class NLUTimeoutError(NLUError):
    """Mistral API timed out."""
    pass


class NLUParseError(NLUError):
    """Mistral returned unparseable output."""
    def __init__(self, raw_output: str, cause: Exception):
        self.raw_output = raw_output
        self.cause      = cause
        super().__init__(f"Failed to parse Mistral output: {cause}")


class NLUSchemaError(NLUError):
    """Mistral output was valid JSON but invalid schema."""
    def __init__(self, data: dict, missing_keys: list):
        self.data         = data
        self.missing_keys = missing_keys
        super().__init__(f"Schema missing required keys: {missing_keys}")


class GroundingError(AgentError):
    """Grounding validation failed unexpectedly."""
    pass


class ContextFetchError(AgentError):
    """Could not fetch live context from FortiGate."""
    pass


class ExecutionBridgeError(AgentError):
    """Could not convert grounded schema to execution format."""
    pass
