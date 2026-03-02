"""
PhishGuard Analyzer Engine
===========================
Main orchestration module that coordinates all analysis components.
"""

import time
from typing import Dict, List, Optional
from datetime import datetime

from .email_fetcher import EmailFetcher
from .authentication_validator import AuthenticationValidator
from .relay_path_analyzer import RelayPathAnalyzer
from .threat_intelligence import ThreatIntelligenceBroker
from .phishing_heuristics import PhishingHeuristics


class PhishGuardAnalyzer:
    """Main analyzer engine for email security analysis"""
    
    def __init__(self, api_keys: Dict = None, cache_file: str = None):
        """
        Initialize the analyzer engine
        
        Args:
            api_keys: Dictionary of API keys for threat intelligence
            cache_file: Path to cache file
        """
        self.auth_validator = AuthenticationValidator()
        self.relay_analyzer = RelayPathAnalyzer()  # ip-api.com — free, no key
        self.threat_intel = ThreatIntelligenceBroker(api_keys=api_keys, cache_file=cache_file)
        self.heuristics = PhishingHeuristics()
        
        self.analysis_stats = {
            'total_analyzed': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'avg_time': 0
        }
    
    def analyze_email(self, email_data: Dict) -> Dict:
        """
        Perform complete analysis on an email
        
        Args:
            email_data: Parsed email data from EmailFetcher
            
        Returns:
            Complete analysis results
        """
        start_time = time.time()
        
        # 1. Validate Authentication (SPF/DKIM/DMARC)
        authentication = self.auth_validator.validate_all(email_data)
        
        # 2. Analyze Relay Path
        relay_path = self.relay_analyzer.analyze_relay_path(
            email_data.get('received_headers', [])
        )
        
        # 3. Check IP Reputation for each hop
        for hop in relay_path:
            ip = hop.get('ip')
            if ip:
                reputation = self.threat_intel.check_ip_reputation(ip)
                hop['reputation_score'] = reputation.get('score', 0)
                hop['reputation_data'] = reputation
        
        # 4. Detect relay anomalies
        relay_anomalies = self.relay_analyzer.detect_relay_anomalies(relay_path)
        
        # 5. Run Phishing Heuristics
        heuristics = self.heuristics.analyze(email_data)
        
        # 6. Check Domain Age
        from_domain = self._extract_domain(email_data.get('from_header', ''))
        domain_info = self.threat_intel.check_domain_age(from_domain)
        
        # 7. Check URL Reputation (Safe Browsing / VirusTotal / offline)
        urls = self._extract_urls(email_data.get('body_text', '') + ' ' + email_data.get('body_html', ''))
        url_reputations = []
        malicious_url_count = 0
        for url in urls[:5]:  # Limit to first 5 URLs
            rep = self.threat_intel.check_url_reputation(url)
            url_reputations.append({'url': url, **rep})
            if rep.get('is_malicious'):
                malicious_url_count += 1
        
        # 8. Calculate Threat Score
        preliminary_data = {
            'authentication': authentication,
            'relay_path': relay_path,
            'from_header': email_data.get('from_header', ''),
            'threat_indicators': {
                'new_domain': domain_info.get('is_new', False),
                'malicious_urls': malicious_url_count,
            }
        }
        
        threat_assessment = self.heuristics.calculate_threat_score(preliminary_data, heuristics)
        
        # Build final result
        analysis_time = round(time.time() - start_time, 2)
        
        result = {
            'message_id': email_data.get('message_id', ''),
            'timestamp': email_data.get('timestamp', ''),
            'analyzed_at': datetime.now().isoformat(),
            'analysis_time_seconds': analysis_time,
            
            # Email metadata
            'from_header': email_data.get('from_header', ''),
            'from_envelope': email_data.get('from_envelope', ''),
            'to': email_data.get('to', ''),
            'subject': email_data.get('subject', ''),
            
            # Authentication results
            'authentication': authentication,
            
            # Relay path
            'relay_path': relay_path,
            'relay_anomalies': relay_anomalies,
            'relay_summary': self.relay_analyzer.get_relay_summary(relay_path),
            
            # Threat intelligence
            'domain_info': domain_info,
            'url_reputations': url_reputations,
            
            # Heuristics
            'threat_indicators': heuristics,
            
            # Final assessment
            'threat_score': threat_assessment['score'],
            'classification': threat_assessment['classification'],
            'scoring_reasons': threat_assessment['reasons']
        }
        
        # Update stats
        self._update_stats(result)
        
        return result
    
    def analyze_eml_file(self, file_path: str) -> Optional[Dict]:
        """Analyze a local .eml file"""
        email_data = EmailFetcher.parse_eml_file(file_path)
        if email_data:
            return self.analyze_email(email_data)
        return None
    
    def analyze_eml_bytes(self, file_bytes: bytes) -> Optional[Dict]:
        """Analyze .eml file from bytes"""
        email_data = EmailFetcher.parse_eml_bytes(file_bytes)
        if email_data:
            return self.analyze_email(email_data)
        return None
    
    def batch_analyze(self, email_data_list: List[Dict]) -> List[Dict]:
        """Analyze multiple emails"""
        results = []
        for email_data in email_data_list:
            result = self.analyze_email(email_data)
            results.append(result)
        return results
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics"""
        return self.analysis_stats.copy()
    
    def _update_stats(self, result: Dict):
        """Update analysis statistics"""
        self.analysis_stats['total_analyzed'] += 1
        
        classification = result.get('classification', '')
        if classification == 'HIGH_RISK_PHISHING':
            self.analysis_stats['high_risk'] += 1
        elif classification == 'MEDIUM_RISK':
            self.analysis_stats['medium_risk'] += 1
        else:
            self.analysis_stats['low_risk'] += 1
        
        # Update average time
        analysis_time = result.get('analysis_time_seconds', 0)
        total = self.analysis_stats['total_analyzed']
        current_avg = self.analysis_stats['avg_time']
        self.analysis_stats['avg_time'] = round(
            ((current_avg * (total - 1)) + analysis_time) / total, 2
        )
    
    def _extract_domain(self, email_address: str) -> str:
        """Extract domain from email address"""
        if not email_address:
            return ''
        
        import re
        match = re.search(r'<([^>]+)>', email_address)
        if match:
            email_address = match.group(1)
        
        if '@' in email_address:
            return email_address.split('@')[1].strip()
        
        return ''
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        import re
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)
    
    def generate_report(self, result: Dict, format: str = 'text') -> str:
        """
        Generate a human-readable report
        
        Args:
            result: Analysis result
            format: 'text' or 'markdown'
            
        Returns:
            Formatted report string
        """
        if format == 'markdown':
            return self._generate_markdown_report(result)
        return self._generate_text_report(result)
    
    def _generate_text_report(self, result: Dict) -> str:
        """Generate plain text report"""
        lines = [
            "=" * 60,
            "PHISHGUARD EMAIL SECURITY ANALYSIS REPORT",
            "=" * 60,
            "",
            f"Message ID: {result.get('message_id', 'N/A')}",
            f"Analyzed: {result.get('analyzed_at', 'N/A')}",
            f"Analysis Time: {result.get('analysis_time_seconds', 0)}s",
            "",
            "-" * 60,
            "THREAT ASSESSMENT",
            "-" * 60,
            f"Score: {result.get('threat_score', 0)}/100",
            f"Classification: {result.get('classification', 'UNKNOWN')}",
            "",
            "-" * 60,
            "AUTHENTICATION RESULTS",
            "-" * 60,
        ]
        
        auth = result.get('authentication', {})
        lines.append(f"SPF: {auth.get('spf', {}).get('result', 'N/A').upper()}")
        lines.append(f"DKIM: {auth.get('dkim', {}).get('result', 'N/A').upper()}")
        lines.append(f"DMARC: {auth.get('dmarc', {}).get('policy', 'N/A').upper()}")
        
        lines.extend([
            "",
            "-" * 60,
            "THREAT INDICATORS",
            "-" * 60,
        ])
        
        indicators = result.get('threat_indicators', {})
        
        lookalike = indicators.get('lookalike_domain', {})
        if lookalike.get('is_lookalike'):
            lines.append(f"⚠️  Lookalike Domain: {lookalike.get('example', '')}")
        
        if indicators.get('sender_mismatch', {}).get('mismatch'):
            lines.append("⚠️  Sender Mismatch: envelope ≠ header")
        
        urgency = indicators.get('urgency_keywords', [])
        if urgency:
            lines.append(f"⚠️  Urgency Keywords: {', '.join(urgency[:5])}")
        
        lines.extend([
            "",
            "-" * 60,
            "RELAY PATH",
            "-" * 60,
        ])
        
        for hop in result.get('relay_path', [])[:5]:
            lines.append(f"  Hop {hop.get('hop')}: {hop.get('ip', 'N/A')} ({hop.get('country', 'Unknown')})")
        
        lines.extend([
            "",
            "=" * 60,
            f"RECOMMENDATION: {'BLOCK' if result.get('threat_score', 0) >= 71 else 'REVIEW' if result.get('threat_score', 0) >= 31 else 'ACCEPT'}",
            "=" * 60,
        ])
        
        return '\n'.join(lines)
    
    def _generate_markdown_report(self, result: Dict) -> str:
        """Generate markdown report"""
        score = result.get('threat_score', 0)
        classification = result.get('classification', 'UNKNOWN')
        
        # Determine color
        if score >= 71:
            color = '🔴'
            recommendation = '**BLOCK** - High risk of phishing'
        elif score >= 31:
            color = '🟠'
            recommendation = '**REVIEW** - Suspicious elements detected'
        else:
            color = '🟢'
            recommendation = '**ACCEPT** - Likely legitimate'
        
        md = f"""# PhishGuard Analysis Report

## Summary

| Metric | Value |
|--------|-------|
| Threat Score | {color} **{score}/100** |
| Classification | **{classification}** |
| Recommendation | {recommendation} |
| Analysis Time | {result.get('analysis_time_seconds', 0)}s |

## Email Details

- **From (Display):** {result.get('from_header', 'N/A')}
- **From (Envelope):** {result.get('from_envelope', 'N/A')}
- **Subject:** {result.get('subject', 'N/A')}
- **Message ID:** `{result.get('message_id', 'N/A')}`

## Authentication Results

"""
        
        auth = result.get('authentication', {})
        spf_result = auth.get('spf', {}).get('result', 'N/A')
        dkim_result = auth.get('dkim', {}).get('result', 'N/A')
        dmarc_result = auth.get('dmarc', {}).get('policy', 'N/A')
        
        spf_icon = '✅' if spf_result == 'pass' else '❌' if spf_result in ['fail', 'softfail'] else '⚪'
        dkim_icon = '✅' if dkim_result == 'pass' else '❌' if dkim_result == 'fail' else '⚪'
        dmarc_icon = '✅' if dmarc_result in ['reject', 'quarantine'] else '⚪' if dmarc_result == 'none' else '❌'
        
        md += f"""
| Protocol | Result | Status |
|----------|--------|--------|
| SPF | {spf_result.upper()} | {spf_icon} |
| DKIM | {dkim_result.upper()} | {dkim_icon} |
| DMARC | {dmarc_result.upper()} | {dmarc_icon} |

## Threat Indicators

"""
        
        indicators = result.get('threat_indicators', {})
        
        lookalike = indicators.get('lookalike_domain', {})
        if lookalike.get('is_lookalike'):
            md += f"- ⚠️ **Lookalike Domain:** {lookalike.get('example', '')}\n"
        
        if indicators.get('sender_mismatch', {}).get('mismatch'):
            md += "- ⚠️ **Sender Mismatch:** Envelope sender differs from header\n"
        
        urgency = indicators.get('urgency_keywords', [])
        if urgency:
            md += f"- ⚠️ **Urgency Keywords:** {', '.join(urgency[:5])}\n"
        
        link_mismatches = indicators.get('link_mismatches', [])
        if link_mismatches:
            md += f"- ⚠️ **Link Mismatches:** {len(link_mismatches)} detected\n"
        
        md += """
## Relay Path

| Hop | IP | Hostname | Country | Reputation |
|-----|-----|----------|---------|------------|
"""
        
        for hop in result.get('relay_path', [])[:5]:
            md += f"| {hop.get('hop')} | {hop.get('ip', 'N/A')} | {hop.get('hostname', 'N/A')[:30]} | {hop.get('country', 'Unknown')} | {hop.get('reputation_score', 0)}/100 |\n"
        
        md += f"""
---
*Report generated by PhishGuard - Email Security Analysis Platform*
"""
        
        return md
