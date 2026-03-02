"""
PhishGuard Modules Package
===========================
Email security analysis modules.
"""

from .email_fetcher import EmailFetcher
from .authentication_validator import AuthenticationValidator
from .relay_path_analyzer import RelayPathAnalyzer
from .threat_intelligence import ThreatIntelligenceBroker
from .phishing_heuristics import PhishingHeuristics
from .analyzer_engine import PhishGuardAnalyzer

__all__ = [
    'EmailFetcher',
    'AuthenticationValidator',
    'RelayPathAnalyzer',
    'ThreatIntelligenceBroker',
    'PhishingHeuristics',
    'PhishGuardAnalyzer'
]
