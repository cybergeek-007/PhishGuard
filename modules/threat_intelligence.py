"""
Threat Intelligence Broker Module
==================================
Integrates external threat intelligence APIs with caching.
"""

import json
import time
import os
import requests
from typing import Dict, Optional, List
from urllib.parse import urlparse
import tldextract


class ThreatIntelligenceBroker:
    """Manages threat intelligence lookups with caching"""
    
    def __init__(self, cache_file: str = None, api_keys: Dict = None):
        """
        Initialize threat intelligence broker
        
        Args:
            cache_file: Path to cache file
            api_keys: Dictionary of API keys
        """
        self.cache_file = cache_file or 'threat_cache.json'
        self.api_keys = api_keys or {}
        self.cache = self._load_cache()

        # Per-service mode — each API can independently be live or demo
        self.abuseipdb_live = bool(self.api_keys.get('abuseipdb'))
        self.safe_browsing_live = bool(self.api_keys.get('safe_browsing'))
        self.virustotal_live = bool(self.api_keys.get('virustotal'))
        self.demo_mode = not (self.abuseipdb_live or self.safe_browsing_live or self.virustotal_live)
        
        if self.demo_mode:
            print("🎭 Threat Intelligence: Running in DEMO mode (no API keys)")
        else:
            live = []
            if self.abuseipdb_live:
                live.append('AbuseIPDB')
            if self.safe_browsing_live:
                live.append('Safe Browsing')
            if self.virustotal_live:
                live.append('VirusTotal')
            print(f"✅ Threat Intelligence: Live APIs → {', '.join(live)}")
    
    def _load_cache(self) -> Dict:
        """Load cache from disk"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save cache to disk"""
        try:
            os.makedirs(os.path.dirname(self.cache_file) or '.', exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"Error saving cache: {e}")
    
    def _get_cached(self, key: str, ttl: int = 86400) -> Optional[Dict]:
        """Get cached result if not expired"""
        if key in self.cache:
            cached_data = self.cache[key]
            if time.time() - cached_data.get('cached_at', 0) < ttl:
                return cached_data.get('result')
        return None
    
    def _set_cached(self, key: str, result: Dict):
        """Store result in cache"""
        self.cache[key] = {
            'result': result,
            'cached_at': time.time()
        }
        self._save_cache()
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """
        Check IP reputation against threat intelligence sources
        
        Args:
            ip_address: IP address to check
            
        Returns:
            dict: {'score': 0-100, 'is_whitelisted': bool, 'sources': []}
        """
        if not ip_address:
            return {'score': 0, 'is_whitelisted': False, 'sources': []}
        
        cache_key = f'ip:{ip_address}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        if self.abuseipdb_live:
            result = self._query_abuseipdb(ip_address)
        else:
            result = self._offline_ip_reputation(ip_address)
        
        self._set_cached(cache_key, result)
        return result
    
    def _query_abuseipdb(self, ip_address: str) -> Dict:
        """Query AbuseIPDB API"""
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return {'score': 0, 'is_whitelisted': False, 'sources': ['No API key']}
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Abuse Confidence Score is 0-100
                confidence = data.get('abuseConfidencePercentage', 0)
                
                result = {
                    'score': confidence,
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', ''),
                    'sources': ['AbuseIPDB']
                }
                
                return result
            
            elif response.status_code == 429:
                print(f"AbuseIPDB rate limit hit for {ip_address}")
                return {'score': 0, 'is_whitelisted': False, 'sources': ['Rate limited']}
            
        except Exception as e:
            print(f"AbuseIPDB error for {ip_address}: {e}")
        
        return {'score': 0, 'is_whitelisted': False, 'sources': ['Error']}
    
    def _offline_ip_reputation(self, ip_address: str) -> Dict:
        """
        Return a neutral result when AbuseIPDB is not configured.
        Does NOT fabricate scores — returns 0 with a clear 'offline' source tag
        so the scoring engine knows this check was not performed.
        """
        return {
            'score': 0,
            'is_whitelisted': False,
            'country': '',
            'isp': '',
            'sources': ['OFFLINE'],
            'note': 'AbuseIPDB API key not configured — IP reputation not checked',
        }
    
    def check_url_reputation(self, url: str) -> Dict:
        """
        Check URL reputation
        
        Args:
            url: URL to check
            
        Returns:
            dict: {'is_malicious': bool, 'threat_types': [], 'sources': []}
        """
        if not url:
            return {'is_malicious': False, 'threat_types': [], 'sources': []}
        
        cache_key = f'url:{url}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        # Try Safe Browsing first, then VirusTotal, then offline
        if self.safe_browsing_live:
            result = self._check_safe_browsing(url)
        elif self.virustotal_live:
            result = self._check_virustotal_url(url)
        else:
            result = self._offline_url_reputation(url)

        # If Safe Browsing said clean but VirusTotal is also available, cross-check
        if (not result.get('is_malicious')
                and self.virustotal_live
                and 'VirusTotal' not in result.get('sources', [])):
            vt_result = self._check_virustotal_url(url)
            if vt_result.get('is_malicious'):
                result = vt_result

        self._set_cached(cache_key, result)
        return result
    
    def _check_safe_browsing(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing"""
        api_key = self.api_keys.get('safe_browsing')
        if not api_key:
            return {'is_malicious': False, 'threat_types': [], 'sources': ['No API key']}
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
            
            payload = {
                'client': {
                    'clientId': 'phishguard',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                if matches:
                    threat_types = [m.get('threatType') for m in matches]
                    return {
                        'is_malicious': True,
                        'threat_types': threat_types,
                        'sources': ['Google Safe Browsing']
                    }
                
                return {
                    'is_malicious': False,
                    'threat_types': [],
                    'sources': ['Google Safe Browsing']
                }
            
        except Exception as e:
            print(f"Safe Browsing error for {url}: {e}")
        
        return {'is_malicious': False, 'threat_types': [], 'sources': ['Error']}
    
    def _offline_url_reputation(self, url: str) -> Dict:
        """
        Return a neutral result when no URL-scanning API is configured.
        Does NOT fabricate scores.
        """
        return {
            'is_malicious': False,
            'threat_types': [],
            'sources': ['OFFLINE'],
            'note': 'No URL-scanning API key configured — URL not checked',
        }

    def _check_virustotal_url(self, url: str) -> Dict:
        """
        Check a URL against VirusTotal's URL scan API.

        Uses the v3 REST API:
          POST /urls          → submit URL for scanning
          GET  /urls/{id}     → retrieve analysis results

        Free tier: 4 req/min, 500 req/day, 15.5K req/month.
        https://docs.virustotal.com/reference/scan-url
        """
        import base64
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'is_malicious': False, 'threat_types': [], 'sources': ['No API key']}

        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json',
        }

        try:
            # ── Step 1: Submit the URL ─────────────────────────────
            submit_resp = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=15,
            )

            if submit_resp.status_code not in (200, 409):
                # 409 = URL already submitted (that's fine, we can still query)
                if submit_resp.status_code == 429:
                    return {'is_malicious': False, 'threat_types': [], 'sources': ['VirusTotal rate-limited']}
                return {'is_malicious': False, 'threat_types': [], 'sources': ['VirusTotal error']}

            # ── Step 2: Get analysis by URL-id ─────────────────────
            # VT URL-id = base64url(url) without trailing '='
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

            analysis_resp = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=15,
            )

            if analysis_resp.status_code == 200:
                data = analysis_resp.json().get('data', {})
                attrs = data.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_engines = sum(stats.values()) if stats else 0

                threat_types = []
                if malicious > 0:
                    threat_types.append(f'MALICIOUS ({malicious}/{total_engines} engines)')
                if suspicious > 0:
                    threat_types.append(f'SUSPICIOUS ({suspicious}/{total_engines} engines)')

                # Flag as malicious if ≥2 engines agree
                is_bad = (malicious + suspicious) >= 2

                return {
                    'is_malicious': is_bad,
                    'threat_types': threat_types,
                    'vt_malicious': malicious,
                    'vt_suspicious': suspicious,
                    'vt_total_engines': total_engines,
                    'sources': ['VirusTotal'],
                }

        except Exception as e:
            print(f"VirusTotal error for {url}: {e}")

        return {'is_malicious': False, 'threat_types': [], 'sources': ['VirusTotal error']}
    
    def check_domain_age(self, domain: str) -> Dict:
        """
        Query domain registration information
        
        Args:
            domain: Domain to check
            
        Returns:
            dict: {'age_days': int, 'is_new': bool, 'registrar': str}
        """
        if not domain:
            return {'age_days': -1, 'is_new': False, 'registrar': 'Unknown'}
        
        cache_key = f'domain:{domain}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        # WHOIS is always free — no API key needed. Try it first.
        result = self._query_whois(domain)
        if result.get('age_days', -1) >= 0:
            self._set_cached(cache_key, result)
            return result

        # WHOIS failed — return unknown instead of fake data
        result = {
            'age_days': -1,
            'is_new': False,
            'registrar': 'Unknown',
            'note': 'WHOIS lookup failed — python-whois may not be installed',
        }
        
        self._set_cached(cache_key, result)
        return result
    
    def _query_whois(self, domain: str) -> Dict:
        """Query WHOIS for domain information"""
        try:
            import whois
            
            w = whois.whois(domain)
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (time.time() - creation_date.timestamp()) / 86400
                
                return {
                    'age_days': int(age_days),
                    'is_new': age_days < 30,
                    'registrar': w.registrar or 'Unknown',
                    'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'Unknown',
                    'expiration_date': w.expiration_date.strftime('%Y-%m-%d') if w.expiration_date else 'Unknown'
                }
        
        except Exception as e:
            print(f"WHOIS error for {domain}: {e}")
        
        return {'age_days': -1, 'is_new': False, 'registrar': 'Unknown'}
    
    def batch_check_ips(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """Check multiple IPs in batch"""
        results = {}
        for ip in ip_addresses:
            if ip:
                results[ip] = self.check_ip_reputation(ip)
        return results
