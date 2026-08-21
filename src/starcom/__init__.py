"""STARCOM proof-gated mission core."""

from .external_evidence import ExternalEvidenceService
from .program import StarcomProgram


__all__ = ["__version__", "ExternalEvidenceService", "StarcomProgram"]
__version__ = "0.1.0"
