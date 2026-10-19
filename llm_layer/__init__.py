"""CrowbarAF LLM katmani: butce-farkinda, kanit-temelli fonksiyon analizi."""
from .client import LLMClient, LLMResult
from .context import build_function_context, findings_for, select_functions, select_with_reasons
from .pipeline import AnalysisResult, analyze
from .summarize import summarize_function
from .tokens import estimate_tokens, truncate_to_tokens
from .trace import Tracer
from .traverse import build_graph, scc_order
from .types import Claim, Finding, FunctionInfo, FunctionSummary
from .verify import verify_claim, verify_claims

__all__ = [
    "LLMClient", "LLMResult", "AnalysisResult", "analyze", "Tracer",
    "Claim", "Finding", "FunctionInfo", "FunctionSummary",
    "build_function_context", "findings_for", "select_functions", "select_with_reasons",
    "summarize_function", "estimate_tokens", "truncate_to_tokens",
    "build_graph", "scc_order", "verify_claim", "verify_claims",
]
