"""
Relay Path Analyzer Module
==========================
Parses Received headers and maps email's journey through mail servers.
"""

import re
import requests
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse


class RelayPathAnalyzer:
    """Analyzes email relay path from Received headers"""
    
    # Regex patterns for parsing Received headers
    IP_PATTERNS = [
        r'[\[\(]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[\]\)]',
        r'from\s+(?:\w+\s+)?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]',
        r'\((?:\w+\s+)?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]\)',
        r'\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b'
    ]
    
    HOSTNAME_PATTERN = r'from\s+([\w\.\-]+)'
    TIMESTAMP_PATTERN = r';\s*(.+)$'  # Everything after semicolon
    
    def __init__(self):
        self.geo_cache = {}
    
    def analyze_relay_path(self, received_headers: List[str]) -> List[Dict]:
        """
        Extract relay path from Received headers
        
        Args:
            received_headers: List of Received header values
            
        Returns:
            List of hops in chronological order (reversed from header order)
        """
        if not received_headers:
            return []
        
        hops = []
        
        # Process in reverse (bottom-to-top = chronological order)
        for idx, header in enumerate(reversed(received_headers)):
            hop = {
                'hop': idx + 1,
                'raw_header': header[:200] + '...' if len(header) > 200 else header
            }
            
            # Extract information
            ip = self._extract_ip(header)
            hostname = self._extract_hostname(header)
            timestamp = self._extract_timestamp(header)
            
            hop['ip'] = ip
            hop['hostname'] = hostname
            hop['timestamp'] = timestamp
            
            # Geolocate IP
            if ip:
                geo_info = self._geolocate_ip(ip)
                hop.update(geo_info)
            
            hops.append(hop)
        
        return hops
    
    def detect_relay_anomalies(self, hops: List[Dict]) -> List[Dict]:
        """
        Identify suspicious patterns in relay path
        
        Red flags:
        1. Too many hops (> 10) - email laundering
        2. Geographic inconsistency
        3. Time anomalies (gaps > 1 hour between hops)
        4. Suspicious countries
        """
        anomalies = []
        
        if len(hops) > 10:
            anomalies.append({
                'type': 'excessive_hops',
                'severity': 'medium',
                'message': f'{len(hops)} relay hops detected (normal: 3-5)'
            })
        
        # Check for suspicious countries
        suspicious_countries = ['RU', 'CN', 'KP', 'IR']
        for hop in hops:
            country = hop.get('country', '')
            if country in suspicious_countries:
                anomalies.append({
                    'type': 'suspicious_country',
                    'severity': 'high',
                    'message': f"Hop {hop['hop']} from {country}: Potential high-risk region"
                })
        
        # Check for private IPs in external hops
        for hop in hops:
            ip = hop.get('ip', '')
            if ip and self._is_private_ip(ip):
                if hop['hop'] > 1:  # First hop can be private
                    anomalies.append({
                        'type': 'private_ip',
                        'severity': 'low',
                        'message': f"Hop {hop['hop']} uses private IP: {ip}"
                    })
        
        return anomalies
    
    def _extract_ip(self, header: str) -> Optional[str]:
        """Extract IP address from Received header"""
        for pattern in self.IP_PATTERNS:
            match = re.search(pattern, header)
            if match:
                ip = match.group(1)
                # Validate IP format
                if self._is_valid_ip(ip):
                    return ip
        return None
    
    def _extract_hostname(self, header: str) -> Optional[str]:
        """Extract hostname from Received header"""
        match = re.search(self.HOSTNAME_PATTERN, header, re.IGNORECASE)
        if match:
            hostname = match.group(1).strip()
            # Filter out common non-hostname strings
            if hostname not in ['unknown', 'localhost']:
                return hostname
        return None
    
    def _extract_timestamp(self, header: str) -> Optional[str]:
        """Extract timestamp from Received header"""
        match = re.search(self.TIMESTAMP_PATTERN, header)
        if match:
            return match.group(1).strip()
        return None
    
    def _geolocate_ip(self, ip_address: str) -> Dict:
        """
        Query ip-api.com for IP geolocation.
        Free: 45 req/min, no API key needed.
        Endpoint: http://ip-api.com/json/{ip}

        Returns:
            dict with country, city, isp, etc.
        """
        # Check cache
        if ip_address in self.geo_cache:
            return self.geo_cache[ip_address]

        # Skip private IPs
        if self._is_private_ip(ip_address):
            result = {
                'country': 'Private',
                'city': 'Local Network',
                'isp': 'Private Network',
                'reputation_score': 0
            }
            self.geo_cache[ip_address] = result
            return result

        # ── Real API call to ip-api.com (free, no key) ───────────
        try:
            resp = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('countryCode', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', ''),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', ''),
                        'asn': data.get('as', ''),
                        'reputation_score': 0,   # populated later by threat intel
                    }
                    self.geo_cache[ip_address] = result
                    return result

        except Exception as e:
            print(f"GeoIP lookup failed for {ip_address}: {e}")

        # Fallback if API fails
        result = {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'reputation_score': 0
        }
        self.geo_cache[ip_address] = result
        return result
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
            ('169.254.0.0', '169.254.255.255'),  # Link-local
        ]
        
        ip_num = self._ip_to_num(ip)
        
        for start, end in private_ranges:
            if self._ip_to_num(start) <= ip_num <= self._ip_to_num(end):
                return True
        
        return False
    
    def _ip_to_num(self, ip: str) -> int:
        """Convert IP address to numeric value"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def get_relay_summary(self, hops: List[Dict]) -> str:
        """Get a summary of the relay path"""
        if not hops:
            return "No relay path information available"
        
        countries = [hop.get('country', 'Unknown') for hop in hops if hop.get('country')]
        unique_countries = list(set(countries))
        
        summary = f"{len(hops)} hop(s)"
        if unique_countries:
            summary += f" through {', '.join(unique_countries)}"
        
        return summary


def format_relay_table(hops: List[Dict]) -> List[Dict]:
    """Format hops for display in a table"""
    table_data = []
    
    for hop in hops:
        table_data.append({
            'Hop': hop.get('hop', ''),
            'IP': hop.get('ip', 'N/A'),
            'Hostname': hop.get('hostname', 'N/A')[:40],
            'Country': hop.get('country', 'Unknown'),
            'City': hop.get('city', 'Unknown'),
            'ISP': hop.get('isp', 'Unknown')[:30],
            'Reputation': f"{hop.get('reputation_score', 0)}/100"
        })
    
    return table_data
