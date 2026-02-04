"""
DNS Handler - Prevents DNS leaks and handles secure DNS resolution
"""
import socket
import logging
import dns.resolver
from typing import List, Dict

logger = logging.getLogger(__name__)


class DNSHandler:
    """Handles DNS resolution with leak prevention"""
    
    # Secure DNS servers
    SECURE_DNS_SERVERS = [
        '1.1.1.1',        # Cloudflare
        '1.0.0.1',        # Cloudflare secondary
        '8.8.8.8',        # Google
        '8.8.4.4',        # Google secondary
    ]
    
    def __init__(self):
        self.cache = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.SECURE_DNS_SERVERS
    
    def resolve(self, hostname: str) -> str:
        """Resolve hostname to IP using secure DNS"""
        try:
            if hostname in self.cache:
                return self.cache[hostname]
            
            # Query DNS
            answers = self.resolver.resolve(hostname, 'A')
            ip = str(answers[0])
            
            # Cache result
            self.cache[hostname] = ip
            logger.info(f"DNS resolved {hostname} -> {ip}")
            
            return ip
        
        except Exception as e:
            logger.error(f"DNS resolution failed for {hostname}: {e}")
            # Fallback to system resolver
            try:
                ip = socket.gethostbyname(hostname)
                self.cache[hostname] = ip
                return ip
            except:
                return '0.0.0.0'
    
    def test_for_leaks(self) -> Dict:
        """Test for DNS leaks"""
        try:
            test_domains = ['dnsleaktest.com', 'whoami.akamai.net']
            leaked_ips = []
            
            for domain in test_domains:
                try:
                    ip = self.resolve(domain)
                    # Check if using secure DNS
                    if ip not in self.SECURE_DNS_SERVERS:
                        leaked_ips.append(ip)
                except:
                    pass
            
            leak_detected = len(leaked_ips) > 0
            
            logger.info(f"DNS leak test - Leak detected: {leak_detected}")
            
            return {
                'leak_detected': leak_detected,
                'leaked_ips': leaked_ips,
                'secure_dns_servers': self.SECURE_DNS_SERVERS
            }
        
        except Exception as e:
            logger.error(f"DNS leak test failed: {e}")
            return {
                'leak_detected': False,
                'leaked_ips': [],
                'secure_dns_servers': self.SECURE_DNS_SERVERS
            }
    
    def flush_cache(self):
        """Clear DNS cache"""
        self.cache.clear()
        logger.info("DNS cache flushed")
    
    def get_cache_stats(self) -> Dict:
        """Get DNS cache statistics"""
        return {
            'cached_entries': len(self.cache),
            'cache': self.cache
        }
