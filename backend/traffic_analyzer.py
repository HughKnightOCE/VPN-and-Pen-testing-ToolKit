"""
Traffic Analyzer - Monitors and analyzes network traffic
"""
import logging
from typing import Dict, List
from collections import deque
from datetime import datetime
import threading

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Analyzes and tracks network traffic"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.history = deque(maxlen=max_history)
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections = {}
        self.lock = threading.Lock()
    
    def log_send(self, bytes_count: int, host: str, port: int):
        """Log outgoing traffic"""
        with self.lock:
            self.bytes_sent += bytes_count
            self.log_connection(host, port, 'send', bytes_count)
    
    def log_receive(self, bytes_count: int, host: str, port: int):
        """Log incoming traffic"""
        with self.lock:
            self.bytes_received += bytes_count
            self.log_connection(host, port, 'receive', bytes_count)
    
    def log_connection(self, host: str, port: int, direction: str, bytes_count: int):
        """Log individual connection"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'host': host,
            'port': port,
            'direction': direction,
            'bytes': bytes_count
        }
        self.history.append(entry)
        
        # Update connection stats
        conn_key = f"{host}:{port}"
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'host': host,
                'port': port,
                'total_bytes': 0,
                'send_bytes': 0,
                'receive_bytes': 0,
                'packet_count': 0
            }
        
        conn = self.connections[conn_key]
        conn['total_bytes'] += bytes_count
        conn['packet_count'] += 1
        
        if direction == 'send':
            conn['send_bytes'] += bytes_count
        else:
            conn['receive_bytes'] += bytes_count
    
    def get_stats(self) -> Dict:
        """Get traffic statistics"""
        with self.lock:
            total_bytes = self.bytes_sent + self.bytes_received
            
            return {
                'total_bytes': total_bytes,
                'bytes_sent': self.bytes_sent,
                'bytes_received': self.bytes_received,
                'active_connections': len(self.connections),
                'total_packets': sum(c['packet_count'] for c in self.connections.values()),
                'connections': list(self.connections.values())[:10]  # Top 10
            }
    
    def get_history(self, limit: int = 100) -> List[Dict]:
        """Get traffic history"""
        with self.lock:
            return list(self.history)[-limit:]
    
    def clear_history(self):
        """Clear traffic history"""
        with self.lock:
            self.history.clear()
            self.bytes_sent = 0
            self.bytes_received = 0
            self.connections.clear()
        logger.info("Traffic history cleared")
    
    def get_bytes_sent(self) -> int:
        """Get total bytes sent"""
        with self.lock:
            return self.bytes_sent
    
    def get_bytes_received(self) -> int:
        """Get total bytes received"""
        with self.lock:
            return self.bytes_received
    
    def get_connection_details(self, host: str, port: int) -> Dict:
        """Get details for specific connection"""
        conn_key = f"{host}:{port}"
        with self.lock:
            return self.connections.get(conn_key, {})
