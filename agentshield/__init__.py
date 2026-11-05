"""AgentShield — AI Agent & MCP Security Assessment Toolkit (static analyzer)."""
from .analyzer import analyze, Report, Finding      # noqa: F401
from .source_scan import scan_source                # noqa: F401

__version__ = "0.2.0"
