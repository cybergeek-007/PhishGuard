"""
Email Fetcher Module
====================
Handles IMAP connections and email retrieval.
"""

import imaplib
import email
from email import policy
from email.parser import BytesParser
from typing import List, Dict, Optional, Tuple
import re
from datetime import datetime


class EmailFetcher:
    """Fetches emails from IMAP servers"""
    
    def __init__(self, server: str, username: str, password: str, port: int = 993, use_ssl: bool = True):
        """
        Initialize IMAP connection
        
        Args:
            server: IMAP server address
            username: Email username
            password: Email password or app password
            port: IMAP port (default 993 for SSL)
            use_ssl: Whether to use SSL/TLS
        """
        self.server = server
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.imap = None
        self.connected = False
        
    def connect(self) -> bool:
        """Establish IMAP connection"""
        try:
            if self.use_ssl:
                self.imap = imaplib.IMAP4_SSL(self.server, self.port)
            else:
                self.imap = imaplib.IMAP4(self.server, self.port)
            
            self.imap.login(self.username, self.password)
            self.connected = True
            return True
        except Exception as e:
            print(f"IMAP Connection Error: {e}")
            return False
    
    def disconnect(self):
        """Close IMAP connection"""
        if self.imap:
            try:
                self.imap.close()
                self.imap.logout()
            except:
                pass
        self.connected = False
    
    def fetch_latest(self, count: int = 10, folder: str = 'INBOX') -> List[Dict]:
        """
        Fetch latest N emails from specified folder
        
        Args:
            count: Number of emails to fetch
            folder: IMAP folder name (default: INBOX)
            
        Returns:
            List of email data dictionaries
        """
        if not self.connected:
            if not self.connect():
                return []
        
        emails = []
        try:
            status, messages = self.imap.select(folder)
            if status != 'OK':
                print(f"Error selecting folder {folder}: {messages}")
                return []
            
            # Get total message count
            status, message_count = self.imap.search(None, 'ALL')
            if status != 'OK':
                return []
            
            message_ids = message_count[0].split()
            latest_ids = message_ids[-count:] if len(message_ids) > count else message_ids
            
            for msg_id in reversed(latest_ids):
                email_data = self._fetch_email_by_id(msg_id)
                if email_data:
                    emails.append(email_data)
                    
        except Exception as e:
            print(f"Error fetching emails: {e}")
        
        return emails
    
    def fetch_by_id(self, message_id: str) -> Optional[Dict]:
        """Fetch specific email by Message-ID header"""
        if not self.connected:
            if not self.connect():
                return None
        
        try:
            status, messages = self.imap.select('INBOX')
            if status != 'OK':
                return None
            
            # Search by Message-ID
            status, msg_nums = self.imap.search(None, f'HEADER Message-ID "{message_id}"')
            if status == 'OK' and msg_nums[0]:
                return self._fetch_email_by_id(msg_nums[0].split()[0])
        except Exception as e:
            print(f"Error fetching email by ID: {e}")
        
        return None
    
    def _fetch_email_by_id(self, msg_id: bytes) -> Optional[Dict]:
        """Fetch and parse a single email by IMAP message ID"""
        try:
            status, msg_data = self.imap.fetch(msg_id, '(RFC822)')
            if status != 'OK':
                return None
            
            raw_email = msg_data[0][1]
            return self.parse_email(raw_email)
            
        except Exception as e:
            print(f"Error parsing email {msg_id}: {e}")
            return None
    
    def parse_email(self, raw_email: bytes) -> Dict:
        """
        Parse raw email bytes into structured dictionary
        
        Args:
            raw_email: Raw email bytes
            
        Returns:
            Dictionary with parsed email data
        """
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        
        # Extract headers
        headers = self._extract_headers(msg)
        
        # Extract body
        body_text, body_html = self._extract_body(msg)
        
        # Parse received headers for relay path
        received_headers = msg.get_all('Received', [])
        
        return {
            'raw_bytes': raw_email,
            'message_id': headers.get('Message-ID', ''),
            'timestamp': headers.get('Date', ''),
            'from_header': headers.get('From', ''),
            'from_envelope': headers.get('Return-Path', headers.get('From', '')),
            'to': headers.get('To', ''),
            'cc': headers.get('Cc', ''),
            'subject': headers.get('Subject', ''),
            'headers': headers,
            'received_headers': received_headers,
            'body_text': body_text,
            'body_html': body_html,
            'attachments': self._extract_attachments(msg)
        }
    
    def _extract_headers(self, msg) -> Dict:
        """Extract all headers from email message"""
        headers = {}
        for key in msg.keys():
            # Decode header values
            value = msg.get(key, '')
            if isinstance(value, str):
                headers[key] = value
            else:
                headers[key] = str(value)
        return headers
    
    def _extract_body(self, msg) -> Tuple[str, str]:
        """Extract text and HTML body from email"""
        text_body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = part.get('Content-Disposition', '')
                
                if 'attachment' not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            decoded = payload.decode(charset, errors='ignore')
                            
                            if content_type == 'text/plain':
                                text_body += decoded
                            elif content_type == 'text/html':
                                html_body += decoded
                    except Exception as e:
                        print(f"Error decoding body part: {e}")
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    decoded = payload.decode(charset, errors='ignore')
                    
                    if msg.get_content_type() == 'text/plain':
                        text_body = decoded
                    elif msg.get_content_type() == 'text/html':
                        html_body = decoded
            except Exception as e:
                print(f"Error decoding body: {e}")
        
        return text_body, html_body
    
    def _extract_attachments(self, msg) -> List[Dict]:
        """Extract attachment information"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get('Content-Disposition', '')
                
                if 'attachment' in content_disposition:
                    filename = part.get_filename()
                    content_type = part.get_content_type()
                    payload = part.get_payload(decode=True)
                    
                    attachments.append({
                        'filename': filename,
                        'content_type': content_type,
                        'size': len(payload) if payload else 0
                    })
        
        return attachments
    
    @staticmethod
    def parse_eml_file(file_path: str) -> Optional[Dict]:
        """Parse a local .eml file"""
        try:
            with open(file_path, 'rb') as f:
                raw_email = f.read()
            
            fetcher = EmailFetcher('', '', '')  # Dummy fetcher for parsing
            return fetcher.parse_email(raw_email)
        except Exception as e:
            print(f"Error parsing .eml file: {e}")
            return None
    
    @staticmethod
    def parse_eml_bytes(file_bytes: bytes) -> Optional[Dict]:
        """Parse .eml file from bytes"""
        try:
            fetcher = EmailFetcher('', '', '')  # Dummy fetcher for parsing
            return fetcher.parse_email(file_bytes)
        except Exception as e:
            print(f"Error parsing .eml bytes: {e}")
            return None


def decode_mime_header(header_value: str) -> str:
    """Decode MIME-encoded header values"""
    if not header_value:
        return ""
    
    decoded_parts = []
    for part, charset in email.header.decode_header(header_value):
        if isinstance(part, bytes):
            try:
                decoded_parts.append(part.decode(charset or 'utf-8', errors='ignore'))
            except:
                decoded_parts.append(part.decode('utf-8', errors='ignore'))
        else:
            decoded_parts.append(part)
    
    return ' '.join(decoded_parts)
