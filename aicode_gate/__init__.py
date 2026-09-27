"""aicode-gate: attribute lines to AI or human authors and gate on vulnerability density in AI-written code."""

__version__ = "0.1.0"


class GateError(Exception):
    """A usage, configuration or environment problem. The CLI reports it and exits 2."""
