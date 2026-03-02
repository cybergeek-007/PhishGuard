# PhishGuard — Email Security Analysis Platform

🛡️ **PhishGuard** is a production-ready email security analysis platform that automates the forensic investigation process typically performed manually by SOC analysts.

## 🎯 Mission

Reduce manual email analysis from **10 minutes to 10 seconds** while maintaining SOC-level accuracy.

**Try it out**: [PhishGuard](https://phisshguard.streamlit.app)

## 🔍 What PhishGuard Analyzes

| Analysis Module | Description | Source |
|----------------|-------------|--------|
| **SPF** | Verify sender IP authorization | `Authentication-Results` header or DNS TXT lookup |
| **DKIM** | Check cryptographic email signatures | `Authentication-Results` header or DNS key check |
| **DMARC** | Validate domain authentication policy | `Authentication-Results` header or `_dmarc.` DNS lookup |
| **IP Reputation** | Abuse confidence score for sending server IPs | **AbuseIPDB API** (live) or offline |
| **URL Blocklist** | Check URLs against Google's global blocklist | **Google Safe Browsing API** (live) or offline |
| **URL Malware Scan** | Multi-engine URL scanning (60+ AV engines) | **VirusTotal API** (live) or offline |
| **IP Geolocation** | Map relay hops to countries / ISPs | **ip-api.com** (free, no key needed) |
| **Domain Age** | Identify newly registered domains | **WHOIS** (free, no key needed) |
| **Lookalike Domains** | DNS-verified brand similarity detection | Levenshtein + MX/A DNS lookups (offline) |
| **URL Analysis** | Detect suspicious / shortened / IP-based links | Pattern analysis (offline) |
| **Link Mismatches** | Visible text ≠ actual href | HTML parsing (offline) |
| **Urgency Keywords** | Social engineering pressure tactics | Regex pattern matching (offline) |

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
cd phishguard

# Install dependencies
pip install -r requirements.txt

# Create your .env file from the template
cp .env.example .env
# Edit .env and paste your API keys (optional — see below)
```

### Environment Variables (`.env`)

Copy `.env.example` → `.env` and fill in your keys. **Every key is optional** — if left blank, that specific check runs in offline mode while everything else still works.

```ini
# AbuseIPDB — IP reputation scoring
# Free: 1,000 checks/day  |  https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=your_key_here

# Google Safe Browsing — URL blocklist lookup
# Free: 10,000 queries/day  |  https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
SAFE_BROWSING_API_KEY=your_key_here

# VirusTotal — URL / domain malware scanning
# Free: 4 lookups/min, 500/day  |  https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_key_here

# NOTE: IP Geolocation uses ip-api.com (free, no API key needed).
```

The dashboard header shows exactly which APIs are live vs offline.

### Launch Dashboard

```bash
streamlit run dashboard.py

# Or use the launcher
python run.py dashboard
```

The dashboard will be available at `http://localhost:8501`

> **Note:** The dashboard uses a **dark-only cybersecurity theme** (green-on-black). Configured in `.streamlit/config.toml`.

### CLI Analysis

```bash
python run.py analyze path/to/email.eml
python run.py test
```

## 📊 Threat Scoring

PhishGuard calculates a composite threat score (0-100):

| Score | Classification | Action |
|-------|---------------|--------|
| 0-30 | LOW_RISK | Likely legitimate |
| 31-70 | MEDIUM_RISK | Review required |
| 71-100 | HIGH_RISK_PHISHING | Likely phishing — Block |

### Scoring Factors

| Factor | Points | Source |
|--------|--------|--------|
| SPF Fail | +30 | Authentication-Results / DNS |
| SPF Softfail | +15 | Authentication-Results / DNS |
| DKIM Fail | +20 | Authentication-Results |
| DMARC Fail | +25 | Authentication-Results / DNS |
| Lookalike Domain (confirmed) | +40 | Levenshtein + DNS MX check |
| Potential Lookalike | +10 | Similar to brand but has valid MX |
| Sender Mismatch | +15 | Header vs envelope comparison |
| New Domain (<30 days) | +25 | WHOIS lookup |
| Suspicious TLD | +15 | `.tk`, `.ml`, `.xyz`, `.ru`, etc. |
| Malicious URLs (Safe Browsing / VirusTotal) | +25 each | **Safe Browsing** or **VirusTotal API** |
| Link Mismatches | +15 each | HTML href analysis (max +30) |
| Suspicious URLs | +10 each | Pattern analysis (max +20) |
| Urgency Keywords | +5 each | Regex matching (max +20) |
| IP Reputation | Up to +50 | **AbuseIPDB API** |
| Trusted Sender | ×0.5 discount | If sender is a known brand |

### How Authentication Works

When you upload a `.eml` file or paste headers, PhishGuard **cannot** re-run SPF from scratch (the original SMTP session is needed). Instead it:

1. **Parses the `Authentication-Results` header** that the receiving MTA (Gmail, Outlook, etc.) already wrote — this is the industry-standard approach used by every SOC tool.
2. If no `Authentication-Results` header exists, falls back to **DNS lookups** for SPF record presence, DKIM selector existence, and DMARC policy.

### DNS-Verified Lookalike Detection

Multi-step approach to minimise false positives:

1. **Exact match** → Domain is a known brand → ✅ Legitimate
2. **Subdomain check** → e.g. `alerts.sbi.co.in` → ✅ Legitimate
3. **Same org, different TLD** + valid MX → ✅ Legitimate
4. **Levenshtein (1-3 edits)** + DNS verification → Smart detection
5. **Brand name embedded** → e.g. `paypal-login.com` → Detected
6. **Suspicious TLD** → `.tk`, `.xyz`, `.ru` → Flagged

### Supported Brands (106+)

Global tech, US banks, **Indian banks** (SBI, HDFC, ICICI, Axis, Kotak, PNB, etc.), **Indian services** (Paytm, PhonePe, Razorpay, Flipkart, Jio, etc.), international banks, and e-commerce.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                          │
│       (IMAP, Gmail API, .eml Upload, Pasted Headers)        │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      PARSER LAYER                           │
│     (Header Extraction, MIME Decoding, Body Parse,          │
│      Smart Header Unfold for pasted input)                  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     ANALYSIS LAYER                          │
│  ┌──────────────────┐ ┌──────────────────┐ ┌─────────────┐  │
│  │ Auth Validator   │ │ Relay Path       │ │ Threat      │  │
│  │ (Auth-Results    │ │ Analyzer         │ │ Intelligence│  │
│  │  header + DNS)   │ │ (ip-api.com Geo) │ │ Broker      │  │
│  └──────────────────┘ └──────────────────┘ └─────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ AbuseIPDB  │ Safe Browsing │ VirusTotal │ WHOIS     │    │
│  │ (IP rep)   │ (URL block)   │ (URL scan) │ (age)     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │   Phishing Heuristics Engine (DNS-verified)         │    │
│  │   • Lookalike detection • Urgency keywords          │    │
│  │   • Link mismatches    • Suspicious URLs            │    │
│  └─────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   PRESENTATION LAYER                        │
│        (Streamlit Dashboard / CLI — Dark Theme)             │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
phishguard/
├── .env.example                  # API key template — copy to .env
├── .gitignore                    # Protects .env from commits
├── .streamlit/
│   └── config.toml               # Forced dark theme config
├── modules/
│   ├── __init__.py
│   ├── email_fetcher.py          # IMAP/email parsing
│   ├── authentication_validator.py # Auth-Results parsing + DNS fallback
│   ├── relay_path_analyzer.py    # Received header analysis + ip-api.com GeoIP
│   ├── threat_intelligence.py    # AbuseIPDB + Safe Browsing + VirusTotal + WHOIS
│   ├── phishing_heuristics.py    # DNS-verified phishing detection
│   └── analyzer_engine.py        # Main orchestration
├── test_data/
│   ├── sample_phishing.eml
│   └── sample_legitimate.eml
├── cache/
│   └── threat_cache.json         # Auto-generated API response cache (24h TTL)
├── config.py                     # Loads .env, brand lists, scoring weights
├── dashboard.py                  # Streamlit UI (dark theme)
├── run.py                        # CLI entry point
└── requirements.txt              # Dependencies
```

## 🔑 API Keys Summary

| Service | What It Does | Free Tier | Key Required? |
|---------|-------------|-----------|---------------|
| **AbuseIPDB** | IP abuse/spam reputation | 1,000 checks/day | Optional |
| **Google Safe Browsing** | URL malware/phishing blocklist | 10,000 queries/day | Optional |
| **ipapi.co** | IP → Country/City/ISP geolocation | 1,000 requests/day | No (free keyless tier) |
| **WHOIS** | Domain registration age | Unlimited | No (uses python-whois) |
| **DNS (MX/A/TXT)** | SPF, DKIM, DMARC, lookalike verification | Unlimited | No |

**All APIs are optional.** Without any keys, PhishGuard still provides:
- Authentication-Results header parsing (SPF/DKIM/DMARC)
- DNS-verified lookalike domain detection
- Link mismatch analysis
- Urgency keyword detection
- Suspicious URL pattern analysis
- WHOIS domain age lookups
- IP geolocation (ipapi.co free tier)

## 🧪 Testing

```bash
python run.py test
python run.py analyze test_data/sample_phishing.eml
python run.py analyze test_data/sample_legitimate.eml
```

## 🛡️ Security Considerations

- API keys are loaded from `.env` file — never commit this file
- `.gitignore` is configured to exclude `.env` and cache files
- Email content is processed locally — no data leaves your system (except API calls you opt into)
- DNS lookups are used only for domain verification (MX/A/TXT records)
- API response cache (24h TTL) reduces external API calls

## 🔮 Future Enhancements

- [ ] YARA rules for attachment scanning
- [ ] Machine learning classification
- [ ] Database storage (PostgreSQL)
- [ ] REST API
- [ ] Slack/Teams integration
- [ ] SIEM integration (Splunk, ELK)
- [ ] Full ARC (Authenticated Received Chain) validation

## 📄 License

MIT License — See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please submit pull requests or open issues.

---

**Built with Python, Streamlit, and ❤️ for email security.**
