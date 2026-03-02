"""
PhishGuard Configuration
========================
Configuration settings for API keys, caching, and analysis parameters.
Loads secrets from a .env file (if present) via python-dotenv.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

# Load .env file if it exists (must come before any os.getenv calls)
try:
    from dotenv import load_dotenv
    load_dotenv()  # reads <project_root>/.env
except ImportError:
    pass  # python-dotenv not installed — fall back to real env vars

# API Keys — each service can be enabled independently.
# A blank / missing key simply means that check falls back to demo mode.
API_KEYS = {
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
    'safe_browsing': os.getenv('SAFE_BROWSING_API_KEY', ''),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
}

# Cache Configuration
CACHE_CONFIG = {
    'ttl': 86400,  # 24 hours
    'storage': os.path.join(os.path.dirname(__file__), 'cache', 'threat_cache.json'),
    'enabled': True
}

# Analysis Settings
@dataclass
class AnalysisConfig:
    """Configuration for email analysis"""
    # Threat Score Weights
    SPF_FAIL_WEIGHT: int = 30
    DKIM_FAIL_WEIGHT: int = 20
    DMARC_FAIL_WEIGHT: int = 25
    SENDER_MISMATCH_WEIGHT: int = 15
    LOOKALIKE_DOMAIN_WEIGHT: int = 40
    NEW_DOMAIN_WEIGHT: int = 25
    SUSPICIOUS_TLD_WEIGHT: int = 15
    LINK_MISMATCH_WEIGHT: int = 30
    URGENCY_KEYWORD_WEIGHT: int = 5  # Per keyword, max 20
    
    # Thresholds
    HIGH_RISK_THRESHOLD: int = 71
    MEDIUM_RISK_THRESHOLD: int = 31
    
    # Domain Age
    NEW_DOMAIN_DAYS: int = 30
    
    # Relay Path
    MAX_NORMAL_HOPS: int = 10
    SUSPICIOUS_HOP_COUNT: int = 10

# Legitimate Brands for Lookalike Detection
LEGITIMATE_BRANDS = [
    # Global tech
    'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'google.com', 'facebook.com', 'meta.com', 'netflix.com',
    'linkedin.com', 'twitter.com', 'instagram.com', 'github.com',
    'dropbox.com', 'adobe.com', 'salesforce.com', 'stripe.com',
    'square.com', 'shopify.com', 'ebay.com', 'etsy.com',
    'spotify.com', 'hulu.com', 'disney.com',
    'zoom.us', 'slack.com', 'atlassian.com',
    'whatsapp.com', 'telegram.org', 'snapchat.com', 'reddit.com',
    'yahoo.com', 'outlook.com', 'protonmail.com',
    # US / global banks
    'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'citibank.com', 'usbank.com', 'capitalone.com',
    'hsbc.com', 'barclays.com', 'standardchartered.com',
    # Indian banks & financial services
    'sbi.co.in', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'kotak.com', 'kotakbank.com',
    'pnbindia.in', 'bankofbaroda.in', 'canarabank.com',
    'idfcfirstbank.com', 'yesbank.in', 'indusind.com',
    # Indian services
    'paytm.com', 'phonepe.com', 'razorpay.com',
    'flipkart.com', 'swiggy.com', 'zomato.com',
    'jio.com', 'airtel.in', 'irctc.co.in',
    'zerodha.com', 'groww.in', 'cred.club',
    # E-commerce & retail
    'walmart.com', 'target.com', 'bestbuy.com', 'alibaba.com',
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn', '.xyz', '.top', '.click']

# Urgency Keywords for Phishing Detection
URGENCY_KEYWORDS = [
    r'\burgent\b', r'\bimmediate action required\b', r'\bsuspended\b',
    r'\bverify now\b', r'\bunusual activity\b', r'\bsecurity alert\b',
    r'\bconfirm your identity\b', r'\baccount locked\b',
    r'\bexpires today\b', r'\bfinal notice\b', r'\bclick here immediately\b',
    r'\bwithin 24 hours\b', r'\bact now\b', r'\blimited time\b',
    r'\baccount will be closed\b', r'\bunauthorized access\b',
    r'\bsuspicious activity\b', r'\bupdate required\b',
    r'\bverify your account\b', r'\bconfirm your details\b'
]

# Trusted Senders (Whitelist)
TRUSTED_SENDERS = [
    'amazon.com', 'google.com', 'microsoft.com', 'apple.com',
    'github.com', 'linkedin.com', 'salesforce.com',
    'netflix.com', 'adobe.com', 'spotify.com', 'dropbox.com',
    # Indian banks & services
    'sbi.co.in', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'kotak.com', 'paytm.com', 'phonepe.com',
    'flipkart.com', 'razorpay.com', 'jio.com', 'airtel.in',
    'irctc.co.in', 'zerodha.com', 'groww.in',
    # Global banks
    'bankofamerica.com', 'chase.com', 'hsbc.com',
    'barclays.com', 'wellsfargo.com',
]

# IMAP Settings
IMAP_CONFIG = {
    'gmail': {
        'server': 'imap.gmail.com',
        'port': 993,
        'use_ssl': True
    },
    'outlook': {
        'server': 'outlook.office365.com',
        'port': 993,
        'use_ssl': True
    },
    'yahoo': {
        'server': 'imap.mail.yahoo.com',
        'port': 993,
        'use_ssl': True
    }
}

# Demo Mode (when no API keys are available)
# Per-service status so the dashboard can show which APIs are live.
API_STATUS = {
    name: ('live' if key else 'demo')
    for name, key in API_KEYS.items()
}
DEMO_MODE = all(v == '' for v in API_KEYS.values())

if DEMO_MODE:
    print("⚠️  Running in DEMO MODE — No API keys found in .env or environment.  Threat intelligence will use offline heuristics only.")
else:
    live = [k for k, v in API_STATUS.items() if v == 'live']
    print(f"✅  API keys loaded for: {', '.join(live)}")
