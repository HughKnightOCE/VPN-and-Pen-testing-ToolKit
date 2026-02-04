"""
Threat Detection Engine
Monitors network traffic patterns for security threats including:
- Port scanning attempts
- Brute force attacks
- DDoS patterns
- Malicious IP connections
- Weak encryption/SSL issues
"""

import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional
import json
import logging
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class Threat:
    """Threat alert object"""
    threat_id: str
    timestamp: str
    threat_type: str  # port_scan, brute_force, ddos, malicious_ip, weak_cipher
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str
    destination_ip: Optional[str]
    details: Dict
    auto_blocked: bool = False
    user_reviewed: bool = False


class ThreatDetector:
    """Real-time threat detection engine"""
    
    def __init__(self):
        self.enabled = True
        self.auto_block_malicious = False
        self.auto_block_brute_force = False
        
        # Detection thresholds
        self.port_scan_threshold = 15  # failed connections
        self.port_scan_window = 60  # seconds
        self.brute_force_threshold = 5  # attempts
        self.brute_force_window = 300  # seconds
        self.ddos_spike_multiplier = 5  # x baseline RPS
        self.ddos_source_threshold = 50  # RPS from single IP
        
        # Tracking structures
        self.failed_connections = defaultdict(deque)  # IP -> deque of timestamps
        self.failed_auth = defaultdict(deque)  # IP -> deque of timestamps
        self.request_rates = defaultdict(list)  # IP -> list of (timestamp, count)
        self.blocked_ips = set()  # IPs to block
        self.threats = deque(maxlen=1000)  # Keep last 1000 threats
        
        # Baseline traffic (packets/sec)
        self.baseline_rps = 100
        self.traffic_history = deque(maxlen=60)  # Last 60 seconds
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Background monitoring thread
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Threat Detection Engine initialized")
    
    def record_failed_connection(self, source_ip: str, destination_ip: str, port: int):
        """Record a failed connection attempt (port scan detection)"""
        if not self.enabled:
            return
        
        with self.lock:
            now = time.time()
            self.failed_connections[source_ip].append((now, destination_ip, port))
            
            # Clean old entries
            while self.failed_connections[source_ip] and \
                  self.failed_connections[source_ip][0][0] < now - self.port_scan_window:
                self.failed_connections[source_ip].popleft()
            
            # Check for port scan
            if len(self.failed_connections[source_ip]) > self.port_scan_threshold:
                self._trigger_port_scan_threat(source_ip, destination_ip)
    
    def record_failed_auth(self, source_ip: str):
        """Record failed authentication attempt (brute force detection)"""
        if not self.enabled:
            return
        
        with self.lock:
            now = time.time()
            self.failed_auth[source_ip].append(now)
            
            # Clean old entries
            while self.failed_auth[source_ip] and \
                  self.failed_auth[source_ip][0] < now - self.brute_force_window:
                self.failed_auth[source_ip].popleft()
            
            # Check for brute force
            if len(self.failed_auth[source_ip]) > self.brute_force_threshold:
                self._trigger_brute_force_threat(source_ip)
    
    def record_traffic(self, source_ip: str, destination_ip: str, bytes_sent: int):
        """Record traffic for DDoS detection"""
        if not self.enabled:
            return
        
        with self.lock:
            now = time.time()
            
            # Track per-IP traffic
            if source_ip not in self.request_rates:
                self.request_rates[source_ip] = []
            
            self.request_rates[source_ip].append((now, bytes_sent))
            
            # Keep only last 60 seconds
            cutoff = now - 60
            self.request_rates[source_ip] = [
                (ts, b) for ts, b in self.request_rates[source_ip] 
                if ts > cutoff
            ]
            
            # Check for DDoS from single source
            recent_bytes = sum(b for _, b in self.request_rates[source_ip])
            if recent_bytes > 1000000:  # 1MB in 60 seconds
                self._trigger_ddos_threat(source_ip, destination_ip, recent_bytes)
    
    def record_weak_cipher(self, source_ip: str, destination_ip: str, cipher: str):
        """Record weak SSL/TLS cipher usage"""
        if not self.enabled:
            return
        
        with self.lock:
            self._add_threat(
                threat_type="weak_cipher",
                severity="MEDIUM",
                source_ip=source_ip,
                destination_ip=destination_ip,
                details={
                    "cipher": cipher,
                    "reason": "Weak or deprecated cipher algorithm"
                },
                auto_blocked=False
            )
    
    def block_ip(self, ip: str, reason: str) -> bool:
        """Add IP to blocklist"""
        with self.lock:
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP: {ip} - Reason: {reason}")
            return True
    
    def unblock_ip(self, ip: str) -> bool:
        """Remove IP from blocklist"""
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                logger.info(f"Unblocked IP: {ip}")
                return True
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        with self.lock:
            return ip in self.blocked_ips
    
    def get_threats(self, limit: int = 100) -> List[Dict]:
        """Get recent threats"""
        with self.lock:
            threats = list(self.threats)[-limit:]
            return [asdict(t) for t in threats]
    
    def get_threat_status(self) -> Dict:
        """Get current threat status"""
        with self.lock:
            critical = sum(1 for t in self.threats if t.severity == "CRITICAL")
            high = sum(1 for t in self.threats if t.severity == "HIGH")
            medium = sum(1 for t in self.threats if t.severity == "MEDIUM")
            low = sum(1 for t in self.threats if t.severity == "LOW")
            
            # Determine overall threat level
            if critical > 0:
                level = "CRITICAL"
            elif high > 2:
                level = "HIGH"
            elif high > 0 or medium > 5:
                level = "MEDIUM"
            else:
                level = "LOW"
            
            return {
                "level": level,
                "total_threats": len(self.threats),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "blocked_ips": len(self.blocked_ips),
                "timestamp": datetime.now().isoformat()
            }
    
    def _trigger_port_scan_threat(self, source_ip: str, destination_ip: str):
        """Record port scanning threat"""
        failed_ports = [port for _, _, port in self.failed_connections[source_ip]]
        
        self._add_threat(
            threat_type="port_scan",
            severity="MEDIUM",
            source_ip=source_ip,
            destination_ip=destination_ip,
            details={
                "failed_attempts": len(self.failed_connections[source_ip]),
                "ports_attempted": list(set(failed_ports)),
                "threshold": self.port_scan_threshold
            },
            auto_blocked=False
        )
    
    def _trigger_brute_force_threat(self, source_ip: str):
        """Record brute force threat"""
        self._add_threat(
            threat_type="brute_force",
            severity="HIGH",
            source_ip=source_ip,
            destination_ip="unknown",
            details={
                "failed_attempts": len(self.failed_auth[source_ip]),
                "threshold": self.brute_force_threshold
            },
            auto_blocked=self.auto_block_brute_force
        )
        
        if self.auto_block_brute_force:
            self.block_ip(source_ip, "Automatic brute force detection")
    
    def _trigger_ddos_threat(self, source_ip: str, destination_ip: str, bytes_sent: int):
        """Record DDoS threat"""
        self._add_threat(
            threat_type="ddos",
            severity="CRITICAL",
            source_ip=source_ip,
            destination_ip=destination_ip,
            details={
                "bytes_sent_60s": bytes_sent,
                "threshold_bytes": 1000000,
                "spike_multiplier": self.ddos_spike_multiplier
            },
            auto_blocked=True
        )
        
        # Auto-block on DDoS
        self.block_ip(source_ip, "DDoS detection threshold exceeded")
    
    def _add_threat(self, threat_type: str, severity: str, source_ip: str, 
                    destination_ip: str, details: Dict, auto_blocked: bool):
        """Add threat to log"""
        threat_id = f"{source_ip}_{int(time.time() * 1000)}"
        
        threat = Threat(
            threat_id=threat_id,
            timestamp=datetime.now().isoformat(),
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            details=details,
            auto_blocked=auto_blocked,
            user_reviewed=False
        )
        
        with self.lock:
            self.threats.append(threat)
        
        logger.warning(f"Threat detected: {severity} - {threat_type} from {source_ip}")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.monitoring:
            try:
                time.sleep(10)
                # Periodic cleanup and analysis
                self._cleanup_old_entries()
            except Exception as e:
                logger.error(f"Error in threat monitoring loop: {e}")
    
    def _cleanup_old_entries(self):
        """Remove old tracking entries"""
        now = time.time()
        cutoff = now - self.port_scan_window
        
        with self.lock:
            # Clean failed connections
            for ip in list(self.failed_connections.keys()):
                self.failed_connections[ip] = deque(
                    [entry for entry in self.failed_connections[ip] if entry[0] > cutoff],
                    maxlen=100
                )
                if not self.failed_connections[ip]:
                    del self.failed_connections[ip]
            
            # Clean failed auth
            cutoff_auth = now - self.brute_force_window
            for ip in list(self.failed_auth.keys()):
                self.failed_auth[ip] = deque(
                    [ts for ts in self.failed_auth[ip] if ts > cutoff_auth],
                    maxlen=100
                )
                if not self.failed_auth[ip]:
                    del self.failed_auth[ip]
    
    def stop(self):
        """Stop the threat detector"""
        self.monitoring = False
        logger.info("Threat Detection Engine stopped")


# Global instance
threat_detector = ThreatDetector()
