```
        ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
        ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
        ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
        ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
        ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
        ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

<p align="center">
  <b>Automated Email Forensics & Phishing Detection Engine</b><br>
  <i>What takes a SOC analyst 10 minutes — PhishGuard does in 10 seconds.</i>
</p>

<p align="center">
  <a href="https://phisshguard.streamlit.app"><img src="https://img.shields.io/badge/LIVE%20DEMO-00ff?style=for-the-badge&logo=streamlit&logoColor=black" alt="Live Demo"></a>
  <img src="https://img.shields.io/badge/python-3.8+-00ff?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-00ff?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/APIs-4%20integrated-00ff?style=for-the-badge" alt="APIs">
</p>

---

## `> whoami`

PhishGuard is an **offensive-grade email forensics platform** built for security professionals, SOC analysts, and anyone who's tired of manually dissecting suspicious emails.

Drop a `.eml` file. Paste raw headers. Get a full forensic breakdown — authentication, relay tracing, threat intelligence, lookalike detection — in seconds. No fluff. No false sense of security. Just data.

---

## `> cat /etc/threat_matrix`

```
┌────────────────────────┬──────────────────────────────────────────┬─────────────────────────────────┐
│ MODULE                 │ DESCRIPTION                              │ SOURCE                          │
├────────────────────────┼──────────────────────────────────────────┼─────────────────────────────────┤
│ SPF Validation         │ Sender IP authorization check            │ Auth-Results header / DNS TXT   │
│ DKIM Verification      │ Cryptographic signature validation       │ Auth-Results header / DNS key   │
│ DMARC Policy           │ Domain authentication policy enforcement │ Auth-Results header / _dmarc.   │
│ IP Reputation          │ Abuse confidence scoring (0-100)         │ AbuseIPDB API                   │
│ URL Blocklist          │ Google's global phishing/malware list    │ Safe Browsing API               │
│ URL Malware Scan       │ Multi-engine scan (60+ AV engines)       │ VirusTotal API v3               │
│ IP Geolocation         │ Map relay hops → country/ISP/ASN         │ ip-api.com (free, no key)       │
│ Domain Age             │ Flag newly registered domains            │ WHOIS (python-whois)            │
│ Lookalike Detection    │ DNS-verified brand impersonation         │ Levenshtein + MX/A DNS probes   │
│ URL Analysis           │ Shortened/IP-based/suspicious links      │ Pattern engine (offline)        │
│ Link Mismatch          │ Visible text ≠ actual href               │ HTML parser (offline)           │
│ Urgency Keywords       │ Social engineering pressure detection    │ Regex engine (offline)          │
└────────────────────────┴──────────────────────────────────────────┴─────────────────────────────────┘
```

---

## `> ./install.sh`

```bash
# Clone the repo
git clone https://github.com/yourusername/phishguard.git
cd phishguard

# Install dependencies
pip install -r requirements.txt

# Set up your environment
cp .env.example .env
nano .env   # paste your API keys (all optional)
```

### Environment Variables

Every key is **optional**. Missing key = that check runs in offline mode. Everything else still works.

```ini
# ──────────────────────────────────────────────────────────
#  PHISHGUARD ENV CONFIG
# ──────────────────────────────────────────────────────────

# AbuseIPDB — IP reputation scoring
# Tier: FREE (1,000 req/day)
# Docs: https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=

# Google Safe Browsing — URL blocklist
# Tier: FREE (10,000 req/day)
# Docs: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
SAFE_BROWSING_API_KEY=

# VirusTotal — Multi-engine URL/domain scanning
# Tier: FREE (4 req/min, 500/day)
# Docs: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=

# ip-api.com  → NO KEY NEEDED (free, 45 req/min)
# WHOIS       → NO KEY NEEDED (python-whois, unlimited)
# DNS lookups → NO KEY NEEDED (SPF/DKIM/DMARC/MX/A)
```

---

## `> streamlit run dashboard.py`

```bash
# Launch the web interface
streamlit run dashboard.py

# Or use the CLI launcher
python run.py dashboard
python run.py analyze path/to/email.eml
python run.py test
```

Dashboard runs at `http://localhost:8501` — dark theme, green-on-black, no light mode. This is a security tool, not a blog.

---

## `> cat /proc/scoring_engine`

### Threat Classification

| Score | Level | Verdict |
|:-----:|:-----:|:--------|
| `0-30` | 🟢 `LOW_RISK` | Probably clean. Pass it through. |
| `31-70` | 🟠 `MEDIUM_RISK` | Suspicious. Needs human eyes. |
| `71-100` | 🔴 `HIGH_RISK_PHISHING` | Kill it. Block the sender. |

### Scoring Breakdown

```
FACTOR                                    POINTS     SOURCE
──────────────────────────────────────────────────────────────
SPF Fail                                  +30        Auth-Results / DNS
SPF Softfail                              +15        Auth-Results / DNS
DKIM Fail                                 +20        Auth-Results
DMARC Fail                                +25        Auth-Results / DNS
Lookalike Domain (confirmed)              +40        Levenshtein + DNS MX
Potential Lookalike                        +10        Similar brand, valid MX
Sender Mismatch (header ≠ envelope)       +15        Header comparison
New Domain (<30 days)                     +25        WHOIS
Suspicious TLD (.tk .ml .xyz .ru)         +15        TLD list
Malicious URL (Safe Browsing/VT)          +25 each   API (max +50)
Link Mismatch (text ≠ href)              +15 each   HTML parse (max +30)
Suspicious URL patterns                   +10 each   Heuristics (max +20)
Urgency Keywords                          +5 each    Regex (max +20)
IP Reputation (AbuseIPDB)                 up to +50  API
──────────────────────────────────────────────────────────────
Trusted Sender Discount                   ×0.5       If domain is a known brand
```

---

## `> tcpdump -i auth0 -vv`

### How Authentication Actually Works

When you upload a `.eml`, PhishGuard **can't** replay the original SMTP session. That's gone. Instead:

1. **Parse `Authentication-Results` header** — written by the receiving MTA (Gmail, O365, etc.) during the live transaction. This is what every real SOC tool does.
2. **DNS Fallback** — if no Auth-Results header exists, we probe:
   - `TXT` records for SPF policy
   - DKIM selector DNS keys
   - `_dmarc.domain.tld` for DMARC policy

### Lookalike Detection Pipeline

```
INPUT: sender domain
   │
   ├─ [1] Exact match against 106+ brands      → ✅ LEGIT
   ├─ [2] Subdomain of known brand             → ✅ LEGIT  (alerts.sbi.co.in)
   ├─ [3] Same org, different TLD + valid MX   → ✅ LEGIT
   ├─ [4] Levenshtein dist 1-3 + DNS verify    → 🔴 PHISH  (paypa1.com → paypal.com)
   ├─ [5] Brand name embedded in domain        → 🔴 PHISH  (paypal-login.com)
   └─ [6] Suspicious TLD                       → 🟠 FLAG   (.tk, .xyz, .ru)
```

**106+ monitored brands:** Global tech, US banks, Indian banks (SBI, HDFC, ICICI, Axis, Kotak, PNB…), Indian services (Paytm, PhonePe, Razorpay, Flipkart, Jio…), international banks, e-commerce.

---

## `> tree /opt/phishguard`

```
phishguard/
├── .env.example                    # API key template
├── .gitignore                      # protects .env, cache, __pycache__
├── .streamlit/
│   └── config.toml                 # forced dark theme
├── config.py                       # dotenv loader, brands, scoring weights
├── dashboard.py                    # Streamlit UI (dark cyber theme)
├── run.py                          # CLI entry point
├── requirements.txt                # deps
├── modules/
│   ├── __init__.py
│   ├── email_fetcher.py            # IMAP / .eml parser
│   ├── authentication_validator.py # Auth-Results parse + DNS fallback
│   ├── relay_path_analyzer.py      # Received headers + ip-api.com GeoIP
│   ├── threat_intelligence.py      # AbuseIPDB + Safe Browsing + VirusTotal + WHOIS
│   ├── phishing_heuristics.py      # DNS-verified lookalike + heuristics engine
│   └── analyzer_engine.py          # orchestrator — wires everything together
├── test_data/
│   ├── sample_phishing.eml         # known-bad sample for testing
│   └── sample_legitimate.eml       # known-good sample
└── cache/
    └── threat_cache.json           # auto-generated, 24h TTL
```

---

## `> nmap -sV --script=api-scan localhost`

| Service | Purpose | Free Tier | Key? |
|---------|---------|-----------|:----:|
| **AbuseIPDB** | IP abuse/spam reputation | 1,000/day | Optional |
| **Google Safe Browsing** | URL phishing/malware blocklist | 10,000/day | Optional |
| **VirusTotal** | Multi-engine URL scanning | 500/day | Optional |
| **ip-api.com** | IP → geo/ISP/ASN mapping | 45/min | ❌ No key |
| **WHOIS** | Domain registration age | Unlimited | ❌ No key |
| **DNS (MX/A/TXT)** | SPF, DKIM, DMARC, lookalike verify | Unlimited | ❌ No key |

**Zero API keys?** PhishGuard still gives you:
- ✅ Authentication-Results header parsing (SPF/DKIM/DMARC)
- ✅ DNS-verified lookalike domain detection (106+ brands)
- ✅ Link mismatch analysis
- ✅ Urgency keyword detection
- ✅ Suspicious URL pattern analysis
- ✅ WHOIS domain age lookups
- ✅ IP geolocation (ip-api.com free tier)
- ✅ Full relay path tracing

---

## `> arch`

```
┌──────────────────────────────────────────────────────────────────┐
│                          INPUT LAYER                             │
│         IMAP  ·  Gmail API  ·  .eml Upload  ·  Paste Headers     │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                         PARSER LAYER                             │
│    Header Extraction  ·  MIME Decode  ·  Body Parse  ·  Unfold   │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                        ANALYSIS LAYER                            │
│                                                                  │
│  ┌─────────────────┐ ┌─────────────────┐ ┌────────────────────┐  │
│  │ AUTH VALIDATOR  │ │ RELAY ANALYZER  │ │ THREAT INTEL       │  │
│  │ Auth-Results +  │ │ ip-api.com geo  │ │ AbuseIPDB          │  │
│  │ DNS fallback    │ │ hop tracing     │ │ Safe Browsing      │  │
│  │ (SPF/DKIM/DMARC)│ │ anomaly detect  │ │ VirusTotal         │  │
│  └─────────────────┘ └─────────────────┘ │ WHOIS              │  │
│                                          └────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │              PHISHING HEURISTICS ENGINE                   │   │
│  │  Lookalike (Levenshtein + DNS)  ·  Urgency keywords       │   │
│  │  Link mismatches  ·  Suspicious URLs  ·  Brand DB (106+)  │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                      PRESENTATION LAYER                          │
│              Streamlit Dashboard  ·  CLI  ·  JSON Export         │
│                   [ dark theme · green-on-black ]                │
└──────────────────────────────────────────────────────────────────┘
```

---

## `> pytest --tb=short`

```bash
python run.py test
python run.py analyze test_data/sample_phishing.eml
python run.py analyze test_data/sample_legitimate.eml
```

---

## `> cat /etc/security/policy.conf`

- API keys loaded from `.env` — **never committed** (`.gitignore` enforced)
- Email content processed **locally** — nothing leaves your box except the API calls you opt into
- DNS lookups are read-only (MX/A/TXT records for verification only)
- API response cache (24h TTL) minimizes external calls
- No telemetry. No tracking. No cloud dependency.

---

## `> cat TODO.md`

- [ ] YARA rules for attachment scanning
- [ ] ML-based classification model
- [ ] PostgreSQL storage backend
- [ ] REST API for integration
- [ ] Slack / Teams alerting
- [ ] SIEM connectors (Splunk, ELK, Sentinel)
- [ ] ARC (Authenticated Received Chain) validation
- [ ] Bulk `.eml` batch processing

---

## `> cat LICENSE`

MIT — do whatever you want. Just don't use it for evil.

---

## `> git log --oneline -1`

**Built with Python, Streamlit, and paranoia.**

*If it looks like a phish and smells like a phish — PhishGuard will catch it.*
