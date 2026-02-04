"""
Alert Handler Module
Email and Slack notifications for security events
"""

import logging
from datetime import datetime
from typing import Dict, List
import json

logger = logging.getLogger(__name__)


class AlertHandler:
    """Centralized alert handler for various notification methods"""
    
    def __init__(self):
        self.alerts_sent = []
        self.email_enabled = False  # Can be enabled via config
        self.slack_enabled = False
    
    def send_alert(self, alert_type: str, severity: str, subject: str, 
                   message: str, details: Dict = None, 
                   methods: List[str] = None) -> bool:
        """Send alert via specified methods (default: logging)"""
        
        if methods is None:
            methods = ['log']  # Default to logging
        
        alert_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': alert_type,
            'severity': severity,
            'subject': subject,
            'message': message,
            'details': details or {}
        }
        
        self.alerts_sent.append(alert_data)
        
        success = True
        
        # Log alert (always)
        self._send_log_alert(alert_data)
        
        # Send via other methods
        for method in methods:
            try:
                if method == 'email' and self.email_enabled:
                    self._send_email_alert(alert_data)
                elif method == 'slack' and self.slack_enabled:
                    self._send_slack_alert(alert_data)
                elif method == 'log':
                    pass  # Already logged
            except Exception as e:
                logger.error(f"Failed to send alert via {method}: {e}")
                success = False
        
        return success
    
    def _send_log_alert(self, alert: Dict):
        """Log alert to application logger"""
        severity_level = {
            'CRITICAL': logging.CRITICAL,
            'HIGH': logging.ERROR,
            'MEDIUM': logging.WARNING,
            'LOW': logging.INFO
        }.get(alert.get('severity', 'LOW'), logging.INFO)
        
        log_message = f"[{alert.get('type')}] {alert.get('subject')} - {alert.get('message')}"
        logger.log(severity_level, log_message)
        
        if alert.get('details'):
            logger.debug(f"Alert details: {json.dumps(alert.get('details'), indent=2)}")
    
    def _send_email_alert(self, alert: Dict):
        """Send email alert (logging-based for now)"""
        # This would integrate with actual email service
        # For now, we log to indicate where email would be sent
        logger.info(f"[EMAIL ALERT] Would send email: {alert.get('subject')}")
        logger.debug(f"Email content: {alert.get('message')}")
    
    def _send_slack_alert(self, alert: Dict):
        """Send Slack alert (logging-based for now)"""
        # This would integrate with Slack webhook
        # For now, we log to indicate where Slack message would be sent
        logger.info(f"[SLACK ALERT] Would send Slack message: {alert.get('subject')}")
    
    def get_alerts(self, limit: int = 100, 
                   alert_type: str = None, 
                   severity: str = None) -> List[Dict]:
        """Get recent alerts"""
        alerts = self.alerts_sent[-limit:]
        
        # Filter by type
        if alert_type:
            alerts = [a for a in alerts if a.get('type') == alert_type]
        
        # Filter by severity
        if severity:
            alerts = [a for a in alerts if a.get('severity') == severity]
        
        return alerts


class ThreatAlertHandler(AlertHandler):
    """Specialized handler for threat-related alerts"""
    
    def alert_port_scan(self, source_ip: str, destination_ip: str, 
                       port_count: int, details: Dict = None):
        """Alert on port scanning activity"""
        return self.send_alert(
            alert_type='port_scan',
            severity='MEDIUM',
            subject=f'Port Scan Detected from {source_ip}',
            message=f'Suspicious port scanning activity detected: {port_count} ports scanned on {destination_ip}',
            details=details or {'source_ip': source_ip, 'destination_ip': destination_ip, 'ports_scanned': port_count},
            methods=['log']
        )
    
    def alert_brute_force(self, source_ip: str, failed_attempts: int, 
                         details: Dict = None):
        """Alert on brute force attempts"""
        return self.send_alert(
            alert_type='brute_force',
            severity='HIGH',
            subject=f'Brute Force Attack from {source_ip}',
            message=f'Multiple failed authentication attempts detected: {failed_attempts} attempts',
            details=details or {'source_ip': source_ip, 'failed_attempts': failed_attempts},
            methods=['log']
        )
    
    def alert_ddos(self, source_ip: str, bytes_sent: int, 
                  details: Dict = None):
        """Alert on DDoS activity"""
        return self.send_alert(
            alert_type='ddos',
            severity='CRITICAL',
            subject=f'DDoS Attack from {source_ip}',
            message=f'Potential DDoS attack detected: {bytes_sent} bytes in 60 seconds',
            details=details or {'source_ip': source_ip, 'bytes_sent': bytes_sent},
            methods=['log']
        )
    
    def alert_malicious_ip(self, source_ip: str, reason: str, 
                          details: Dict = None):
        """Alert on malicious IP detection"""
        return self.send_alert(
            alert_type='malicious_ip',
            severity='CRITICAL',
            subject=f'Malicious IP Blocked: {source_ip}',
            message=f'Connection from malicious IP blocked: {reason}',
            details=details or {'source_ip': source_ip, 'reason': reason},
            methods=['log']
        )


class SecurityAlertHandler(AlertHandler):
    """Specialized handler for security test alerts"""
    
    def alert_vulnerability_found(self, test_type: str, target: str, 
                                 vulnerability: str, severity: str,
                                 details: Dict = None):
        """Alert when vulnerability is found during testing"""
        return self.send_alert(
            alert_type='vulnerability_found',
            severity=severity,
            subject=f'{test_type.upper()} Vulnerability Found on {target}',
            message=f'Vulnerability detected during security testing: {vulnerability}',
            details=details or {'test_type': test_type, 'target': target, 'vulnerability': vulnerability},
            methods=['log']
        )
    
    def alert_test_completed(self, test_type: str, target: str, 
                            vulnerability_count: int, details: Dict = None):
        """Alert when security test completes"""
        severity = 'CRITICAL' if vulnerability_count > 5 else 'HIGH' if vulnerability_count > 2 else 'MEDIUM'
        
        return self.send_alert(
            alert_type='test_completed',
            severity=severity,
            subject=f'{test_type.upper()} Test Completed: {vulnerability_count} vulnerabilities found',
            message=f'Security test on {target} completed with {vulnerability_count} vulnerabilities found',
            details=details or {'test_type': test_type, 'target': target, 'vulnerability_count': vulnerability_count},
            methods=['log']
        )


# Global instances
threat_alert_handler = ThreatAlertHandler()
security_alert_handler = SecurityAlertHandler()
