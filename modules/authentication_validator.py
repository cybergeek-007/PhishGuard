"""
Authentication Validator Module
===============================
Validates SPF, DKIM, and DMARC authentication for emails.

Strategy
--------
When analysing a saved .eml or pasted headers we do NOT have a live SMTP
session, so we CANNOT re-run SPF checks from scratch (the receiving MTA
already did that).  The correct approach is:

  1. **Parse the Authentication-Results header** that the receiving MTA wrote.
     This is the industry-standard way every SOC tool reads auth results from
     exported emails.
  2. If no Authentication-Results header exists, fall back to DNS look-ups
     for DMARC policy and DKIM selector presence.
"""

import re
import dns.resolver
import dns.exception
from typing import Dict, Optional, Tuple, List


class AuthenticationValidator:
    """Validates email authentication mechanisms"""

    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        # Use public DNS servers as fallback (some networks/firewalls block DNS)
        self.dns_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']

    # ── Public API ───────────────────────────────────────────────────

    def validate_all(self, email_data: Dict) -> Dict:
        """
        Run all authentication checks.

        First tries to extract results from the *Authentication-Results*
        header (the authoritative source for saved/forwarded emails).
        Falls back to DNS look-ups where possible.
        """
        raw_bytes = email_data.get('raw_bytes', b'')
        headers = email_data.get('headers', {})
        auth_results_header = headers.get(
            'Authentication-Results',
            headers.get('authentication-results', '')
        )

        # If there's a multi-valued header, take the first (most authoritative)
        if isinstance(auth_results_header, list):
            auth_results_header = auth_results_header[0]

        header_from = self._extract_domain_from_email(
            email_data.get('from_header', '')
        )
        envelope_from = self._extract_envelope_from(
            email_data.get('from_envelope', '')
        )

        # ── Approach 1: Parse Authentication-Results header ──────
        if auth_results_header:
            parsed = self._parse_authentication_results(auth_results_header)
            spf_result = parsed.get('spf', {'result': 'none', 'reason': 'Not found in Authentication-Results'})
            dkim_result = parsed.get('dkim', {'result': 'none', 'reason': 'Not found in Authentication-Results'})
            dmarc_result = parsed.get('dmarc', {'policy': 'none', 'reason': 'Not found in Authentication-Results'})
        else:
            # ── Approach 2: Offline DNS checks ───────────────────
            spf_result = self._check_spf_record_exists(header_from or envelope_from)
            dkim_result = self._check_dkim_from_email(raw_bytes)
            dmarc_result = self._check_dmarc_dns(header_from)

        return {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
            'arc': {'result': 'none', 'reason': 'ARC not implemented'},
        }

    # ── Authentication-Results header parser ─────────────────────

    def _parse_authentication_results(self, header: str) -> Dict:
        """
        Parse an Authentication-Results header.

        Example header value:
            mx.google.com;
              spf=pass (google.com: domain of user@example.com designates
                        93.184.216.34 as permitted sender) smtp.mailfrom=example.com;
              dkim=pass header.d=example.com header.s=selector1;
              dmarc=pass (p=REJECT) header.from=example.com
        """
        results: Dict = {}

        # Normalise whitespace
        header = ' '.join(header.split())

        # SPF
        spf_m = re.search(
            r'\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)',
            header, re.IGNORECASE
        )
        if spf_m:
            results['spf'] = {
                'result': spf_m.group(1).lower(),
                'reason': f'From Authentication-Results header (spf={spf_m.group(1).lower()})',
            }

        # DKIM
        dkim_m = re.search(
            r'\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror|policy)',
            header, re.IGNORECASE
        )
        if dkim_m:
            selector = None
            domain = None
            sel_m = re.search(r'header\.s\s*=\s*([\w.-]+)', header, re.IGNORECASE)
            dom_m = re.search(r'header\.d\s*=\s*([\w.-]+)', header, re.IGNORECASE)
            if sel_m:
                selector = sel_m.group(1)
            if dom_m:
                domain = dom_m.group(1)
            results['dkim'] = {
                'result': dkim_m.group(1).lower(),
                'reason': f'From Authentication-Results header (dkim={dkim_m.group(1).lower()})',
                'selector': selector,
                'domain': domain,
            }

        # DMARC
        dmarc_m = re.search(
            r'\bdmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)',
            header, re.IGNORECASE
        )
        if dmarc_m:
            # Try to extract the policy from (p=REJECT) / (p=QUARANTINE)
            policy_m = re.search(r'\(p\s*=\s*(\w+)\)', header, re.IGNORECASE)
            policy = policy_m.group(1).lower() if policy_m else dmarc_m.group(1).lower()
            results['dmarc'] = {
                'result': dmarc_m.group(1).lower(),
                'policy': policy,
                'reason': f'From Authentication-Results header (dmarc={dmarc_m.group(1).lower()}, p={policy})',
            }

        return results

    # ── Offline DNS fallbacks ────────────────────────────────────

    def _check_spf_record_exists(self, domain: str) -> Dict:
        """Check if the sender domain publishes an SPF record (TXT)."""
        if not domain:
            return {'result': 'none', 'reason': 'No sender domain available'}

        try:
            answers = self.dns_resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    # We found an SPF record — but we can't validate it
                    # without the original SMTP session IP.
                    mechanisms = txt
                    has_hard_fail = '-all' in txt
                    has_soft_fail = '~all' in txt
                    return {
                        'result': 'record_found',
                        'reason': (
                            f'SPF record found for {domain} '
                            f'({"strict -all" if has_hard_fail else "soft ~all" if has_soft_fail else "permissive"}). '
                            f'Full validation requires original SMTP session.'
                        ),
                        'raw_record': mechanisms,
                    }
            return {'result': 'none', 'reason': f'No SPF record published for {domain}'}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {'result': 'none', 'reason': f'No DNS records for {domain}'}
        except dns.exception.Timeout:
            return {'result': 'temperror', 'reason': 'DNS timeout checking SPF'}
        except Exception as e:
            return {'result': 'error', 'reason': str(e)}

    def _check_dkim_from_email(self, raw_email: bytes) -> Dict:
        """Extract DKIM-Signature info from the email (cannot fully verify offline)."""
        if not raw_email:
            return {'result': 'none', 'reason': 'No email data provided'}

        if b'DKIM-Signature:' not in raw_email and b'dkim-signature:' not in raw_email:
            return {'result': 'none', 'reason': 'No DKIM signature present in email'}

        selector, domain = self._extract_dkim_info(raw_email)

        # Try to verify the DKIM selector exists in DNS
        if selector and domain:
            try:
                self.dns_resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                return {
                    'result': 'signature_present',
                    'reason': f'DKIM signature found (s={selector}, d={domain}). DNS key exists.',
                    'selector': selector,
                    'domain': domain,
                }
            except Exception:
                return {
                    'result': 'signature_present',
                    'reason': f'DKIM signature found (s={selector}, d={domain}). Could not verify DNS key.',
                    'selector': selector,
                    'domain': domain,
                }

        return {
            'result': 'signature_present',
            'reason': 'DKIM signature found but could not parse selector/domain',
            'selector': selector,
            'domain': domain,
        }

    def _check_dmarc_dns(self, domain: str) -> Dict:
        """Query DMARC TXT record from DNS."""
        if not domain:
            return {'policy': 'none', 'reason': 'No domain provided'}

        try:
            answers = self.dns_resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    return self._parse_dmarc_record(txt, domain)
            return {'policy': 'none', 'reason': f'No DMARC record for {domain}'}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {'policy': 'none', 'reason': f'No DMARC record for {domain}'}
        except dns.exception.Timeout:
            return {'policy': 'none', 'reason': 'DNS timeout checking DMARC'}
        except Exception as e:
            return {'policy': 'none', 'reason': str(e)}
    
    def _parse_dmarc_record(self, record: str, domain: str = '') -> Dict:
        """Parse DMARC TXT record"""
        result = {
            'policy': 'none',
            'percentage': 100,
            'reporting_address': None,
            'raw_record': record
        }
        
        # Parse key-value pairs
        parts = record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'p':
                    result['policy'] = value.lower()
                elif key == 'pct':
                    try:
                        result['percentage'] = int(value)
                    except:
                        pass
                elif key == 'rua':
                    result['reporting_address'] = value
        
        result['reason'] = f"Policy: {result['policy']}, Percentage: {result['percentage']}% (from DNS _dmarc.{domain})"
        result['result'] = 'record_found'
        return result
    
    def _extract_sender_ip(self, received_headers: list) -> str:
        """Extract sender IP from Received headers"""
        if not received_headers:
            return ''
        
        # Get the last (oldest) Received header - this is the first hop
        last_header = received_headers[-1] if received_headers else ''
        
        # Extract IP address using regex
        ip_pattern = r'[\[\(]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[\]\)]'
        match = re.search(ip_pattern, last_header)
        
        if match:
            return match.group(1)
        
        # Try alternative pattern
        alt_pattern = r'from\s+\S+\s+\(?\s*\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?\s*\)?'
        match = re.search(alt_pattern, last_header)
        
        return match.group(1) if match else ''
    
    def _extract_envelope_from(self, return_path: str) -> str:
        """Extract email address from Return-Path or similar"""
        if not return_path:
            return ''
        
        # Extract email from <address> format
        match = re.search(r'<([^>]+)>', return_path)
        if match:
            return match.group(1)
        
        # If no brackets, assume it's the email itself
        if '@' in return_path:
            return return_path.strip()
        
        return ''
    
    def _extract_domain_from_email(self, email_address: str) -> str:
        """Extract domain from email address"""
        if not email_address:
            return ''
        
        # Extract email from "Name <email>" format
        match = re.search(r'<([^>]+)>', email_address)
        if match:
            email_address = match.group(1)
        
        # Extract domain
        if '@' in email_address:
            return email_address.split('@')[1].strip()
        
        return ''
    
    def _extract_dkim_info(self, raw_email: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Extract DKIM selector and domain from signature"""
        try:
            email_str = raw_email.decode('utf-8', errors='ignore')
            
            # Find DKIM-Signature header
            dkim_match = re.search(r'DKIM-Signature:[^\n]+', email_str, re.IGNORECASE)
            if dkim_match:
                header = dkim_match.group(0)
                
                # Extract selector (s=)
                selector_match = re.search(r'\bs=([^;\s]+)', header)
                selector = selector_match.group(1) if selector_match else None
                
                # Extract domain (d=)
                domain_match = re.search(r'\bd=([^;\s]+)', header)
                domain = domain_match.group(1) if domain_match else None
                
                return selector, domain
        except:
            pass
        
        return None, None


def get_authentication_summary(auth_results: Dict) -> str:
    """Get a human-readable summary of authentication results"""
    spf = auth_results.get('spf', {}).get('result', 'none')
    dkim = auth_results.get('dkim', {}).get('result', 'none')
    dmarc = auth_results.get('dmarc', {}).get('policy', 'none')
    
    spf_icon = '✅' if spf == 'pass' else '❌' if spf in ['fail', 'softfail'] else '⚪'
    dkim_icon = '✅' if dkim == 'pass' else '❌' if dkim == 'fail' else '⚪'
    dmarc_icon = '✅' if dmarc in ['reject', 'quarantine'] else '⚪' if dmarc == 'none' else '❌'
    
    return f"SPF: {spf_icon} {spf.upper()} | DKIM: {dkim_icon} {dkim.upper()} | DMARC: {dmarc_icon} {dmarc.upper()}"
