"""
Main Flask server for VPN Proxy + Pentesting Toolkit
Handles API routes and manages proxy/pentesting operations
"""
import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import logging
from threading import Thread
import time

# Import custom modules
from proxy import SOCKSProxyServer
from encryption import EncryptionManager
from dns_handler import DNSHandler
from traffic_analyzer import TrafficAnalyzer
from threat_detector import threat_detector
from database import init_db, get_db, User, TestResult, Report, AuditLog
from auth import AuthManager, token_required, role_required
from rate_limiter import rate_limiter
from alert_handler import threat_alert_handler, security_alert_handler
from report_generator import report_generator
from pentesting.sql_tester import SQLTester
from pentesting.xss_tester import XSSTester
from pentesting.port_scanner import PortScanner
from pentesting.cert_analyzer import CertificateAnalyzer
from pentesting.interceptor import RequestInterceptor

# Configuration
load_dotenv()
app = Flask(__name__)
CORS(app)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize database
try:
    init_db()
except Exception as e:
    logger.warning(f"Database initialization skipped: {e}")

# Initialize core components
encryption_manager = EncryptionManager()
dns_handler = DNSHandler()
traffic_analyzer = TrafficAnalyzer()
proxy_server = None
proxy_thread = None

# Initialize pentesting tools
sql_tester = SQLTester()
xss_tester = XSSTester()
port_scanner = PortScanner()
cert_analyzer = CertificateAnalyzer()
request_interceptor = RequestInterceptor()

# Global state
vpn_active = False
kill_switch_enabled = False


# ==================== Rate Limiting Middleware ====================

@app.before_request
def apply_rate_limit():
    """Apply rate limiting to all requests"""
    # Skip for auth and health endpoints
    if request.path in ['/api/auth/login', '/api/auth/register', '/api/health']:
        return
    
    identifier = request.remote_addr or 'unknown'
    if not rate_limiter.is_allowed(identifier):
        return jsonify({'error': 'Rate limit exceeded', 'retry_after': 60}), 429


# ==================== Authentication Routes ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not all([username, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        db = next(get_db())
        auth_manager = AuthManager(db)
        result = auth_manager.register_user(username, email, password)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({'error': 'Missing credentials'}), 400
    
    try:
        db = next(get_db())
        auth_manager = AuthManager(db)
        result = auth_manager.login_user(username, password)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/auth/user', methods=['GET'])
@token_required
def get_user(payload):
    """Get current user info"""
    try:
        db = next(get_db())
        auth_manager = AuthManager(db)
        user_id = payload.get('user_id')
        user = auth_manager.get_user(user_id)
        
        if user:
            return jsonify(user), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password(payload):
    """Change user password"""
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not all([old_password, new_password]):
        return jsonify({'error': 'Missing fields'}), 400
    
    try:
        db = next(get_db())
        auth_manager = AuthManager(db)
        user_id = payload.get('user_id')
        result = auth_manager.change_password(user_id, old_password, new_password)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== VPN Routes ====================

@app.before_request
def apply_rate_limit():
    """Apply rate limiting to all requests"""
    # Skip for auth and health endpoints
    if request.path in ['/api/auth/login', '/api/auth/register', '/api/health']:
        return
    
    identifier = request.remote_addr or 'unknown'
    if not rate_limiter.is_allowed(identifier):
        return jsonify({'error': 'Rate limit exceeded', 'retry_after': 60}), 429


# ==================== VPN Routes ====================

@app.route('/api/vpn/status', methods=['GET'])
def vpn_status():
    """Get current VPN status"""
    return jsonify({
        'active': vpn_active,
        'kill_switch': kill_switch_enabled,
        'uptime': get_vpn_uptime(),
        'bytes_sent': traffic_analyzer.get_bytes_sent(),
        'bytes_received': traffic_analyzer.get_bytes_received(),
        'ip_masked': vpn_active
    })


@app.route('/api/vpn/start', methods=['POST'])
def start_vpn():
    """Start VPN proxy server"""
    global vpn_active, proxy_server, proxy_thread
    
    if vpn_active:
        return jsonify({'error': 'VPN already running'}), 400
    
    try:
        proxy_server = SOCKSProxyServer(
            host='127.0.0.1',
            port=9050,
            encryption_manager=encryption_manager,
            dns_handler=dns_handler,
            traffic_analyzer=traffic_analyzer
        )
        
        proxy_thread = Thread(target=proxy_server.run, daemon=True)
        proxy_thread.start()
        vpn_active = True
        
        logger.info("VPN proxy started successfully")
        return jsonify({
            'status': 'VPN started',
            'proxy_address': '127.0.0.1:9050'
        })
    except Exception as e:
        logger.error(f"Failed to start VPN: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vpn/stop', methods=['POST'])
def stop_vpn():
    """Stop VPN proxy server"""
    global vpn_active, proxy_server
    
    if not vpn_active:
        return jsonify({'error': 'VPN not running'}), 400
    
    try:
        if proxy_server:
            proxy_server.stop()
        vpn_active = False
        logger.info("VPN proxy stopped")
        return jsonify({'status': 'VPN stopped'})
    except Exception as e:
        logger.error(f"Failed to stop VPN: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vpn/kill-switch', methods=['POST'])
def toggle_kill_switch():
    """Enable/disable kill switch"""
    global kill_switch_enabled
    
    data = request.json
    enable = data.get('enable', False)
    
    kill_switch_enabled = enable
    logger.info(f"Kill switch {'enabled' if enable else 'disabled'}")
    
    return jsonify({
        'kill_switch': kill_switch_enabled,
        'status': 'Kill switch ' + ('enabled' if enable else 'disabled')
    })


@app.route('/api/vpn/dns-leak-test', methods=['GET'])
def dns_leak_test():
    """Test for DNS leaks"""
    try:
        results = dns_handler.test_for_leaks()
        return jsonify({
            'leak_detected': results['leak_detected'],
            'leaked_ips': results['leaked_ips'],
            'status': 'DNS protected' if not results['leak_detected'] else 'DNS leak detected'
        })
    except Exception as e:
        logger.error(f"DNS leak test failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ==================== Traffic Monitoring Routes ====================

@app.route('/api/traffic/stats', methods=['GET'])
def traffic_stats():
    """Get traffic statistics"""
    return jsonify(traffic_analyzer.get_stats())


@app.route('/api/traffic/history', methods=['GET'])
def traffic_history():
    """Get traffic history"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify({
        'history': traffic_analyzer.get_history(limit)
    })


@app.route('/api/traffic/clear', methods=['POST'])
def clear_traffic():
    """Clear traffic history"""
    traffic_analyzer.clear_history()
    return jsonify({'status': 'Traffic history cleared'})


# ==================== Pentesting Routes ====================

@app.route('/api/pentest/sql-injection', methods=['POST'])
def test_sql_injection():
    """Test URL for SQL injection vulnerabilities"""
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    try:
        results = sql_tester.test_url(url)
        return jsonify({
            'url': url,
            'vulnerable': results['vulnerable'],
            'payloads_tested': results['payloads_tested'],
            'vulnerable_params': results['vulnerable_params'],
            'results': results['results']
        })
    except Exception as e:
        logger.error(f"SQL injection test failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentest/xss-test', methods=['POST'])
def test_xss():
    """Test for XSS vulnerabilities"""
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    try:
        results = xss_tester.test_url(url)
        return jsonify({
            'url': url,
            'vulnerable': results['vulnerable'],
            'payloads_tested': results['payloads_tested'],
            'vulnerable_params': results['vulnerable_params']
        })
    except Exception as e:
        logger.error(f"XSS test failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentest/port-scan', methods=['POST'])
def scan_ports():
    """Scan host for open ports"""
    data = request.json
    host = data.get('host')
    ports = data.get('ports', '1-1000')
    
    if not host:
        return jsonify({'error': 'Host required'}), 400
    
    try:
        results = port_scanner.scan(host, ports)
        return jsonify({
            'host': host,
            'open_ports': results['open_ports'],
            'closed_ports': results['closed_ports'],
            'services': results['services']
        })
    except Exception as e:
        logger.error(f"Port scan failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentest/cert-analyze', methods=['POST'])
def analyze_certificate():
    """Analyze SSL/TLS certificate"""
    data = request.json
    host = data.get('host')
    port = data.get('port', 443)
    
    if not host:
        return jsonify({'error': 'Host required'}), 400
    
    try:
        results = cert_analyzer.analyze(host, port)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Certificate analysis failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentest/intercept/start', methods=['POST'])
def start_intercept():
    """Start request interception"""
    try:
        request_interceptor.start()
        return jsonify({'status': 'Interception started'})
    except Exception as e:
        logger.error(f"Failed to start interception: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentest/intercept/stop', methods=['POST'])
def stop_intercept():
    """Stop request interception"""
    try:
        request_interceptor.stop()
        return jsonify({'status': 'Interception stopped'})
    except Exception as e:
        logger.error(f"Failed to stop interception: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentest/intercept/requests', methods=['GET'])
def get_intercepted_requests():
    """Get intercepted requests"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify({
        'requests': request_interceptor.get_requests(limit)
    })


# ==================== Helper Routes ====================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time()
    })


@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current settings"""
    return jsonify({
        'proxy_port': 9050,
        'encryption': 'AES-256',
        'dns_protection': True,
        'kill_switch': kill_switch_enabled
    })


# ==================== Helper Functions ====================

def get_vpn_uptime():
    """Get VPN uptime in seconds"""
    if not vpn_active or not proxy_server:
        return 0
    return proxy_server.get_uptime()


# ==================== Threat Detection Routes ====================

@app.route('/api/threats/status', methods=['GET'])
def get_threat_status():
    """Get current threat status"""
    return jsonify(threat_detector.get_threat_status())


@app.route('/api/threats/alerts', methods=['GET'])
def get_threats():
    """Get threat alerts"""
    limit = request.args.get('limit', 100, type=int)
    threats = threat_detector.get_threats(limit)
    return jsonify({'threats': threats, 'total': len(threats)})


@app.route('/api/threats/block', methods=['POST'])
def block_ip():
    """Block an IP address"""
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block')
    action = data.get('action', 'block')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    if action == 'block':
        threat_detector.block_ip(ip, reason)
        return jsonify({'status': 'success', 'message': f'Blocked {ip}'})
    elif action == 'unblock':
        if threat_detector.unblock_ip(ip):
            return jsonify({'status': 'success', 'message': f'Unblocked {ip}'})
        else:
            return jsonify({'error': 'IP not in blocklist'}), 400
    else:
        return jsonify({'error': 'Invalid action'}), 400


@app.route('/api/threats/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    return jsonify({'blocked_ips': list(threat_detector.blocked_ips)})


@app.route('/api/threats/record-failed-connection', methods=['POST'])
def record_failed_connection():
    """Record a failed connection attempt"""
    data = request.json
    source_ip = data.get('source_ip')
    destination_ip = data.get('destination_ip')
    port = data.get('port', 0)
    
    if source_ip and destination_ip:
        threat_detector.record_failed_connection(source_ip, destination_ip, port)
        return jsonify({'status': 'recorded'})
    
    return jsonify({'error': 'Missing required fields'}), 400


@app.route('/api/threats/record-traffic', methods=['POST'])
def record_traffic():
    """Record traffic for analysis"""
    data = request.json
    source_ip = data.get('source_ip')
    destination_ip = data.get('destination_ip')
    bytes_sent = data.get('bytes_sent', 0)
    
    if source_ip and destination_ip:
        threat_detector.record_traffic(source_ip, destination_ip, bytes_sent)
        return jsonify({'status': 'recorded'})
    
    return jsonify({'error': 'Missing required fields'}), 400


# ==================== Reporting Routes ====================

@app.route('/api/reports/generate', methods=['POST'])
@token_required
@role_required('tester')
def generate_report(payload):
    """Generate security report"""
    data = request.json
    title = data.get('title', 'Security Assessment Report')
    test_results = data.get('test_results', [])
    report_type = data.get('report_type', 'summary')
    company_name = data.get('company_name', 'Security Team')
    
    result = report_generator.generate_report(
        report_id=int(time.time() * 1000),
        title=title,
        test_results=test_results,
        report_type=report_type,
        company_name=company_name,
        include_html=True,
        include_pdf=False
    )
    
    return jsonify(result), 201 if result['success'] else 500


@app.route('/api/reports/list', methods=['GET'])
@token_required
def list_reports(payload):
    """List all reports for user"""
    try:
        db = next(get_db())
        user_id = payload.get('user_id')
        
        reports = db.query(Report).filter(Report.user_id == user_id).all()
        
        return jsonify({
            'reports': [
                {
                    'id': r.id,
                    'title': r.title,
                    'created_at': r.created_at.isoformat(),
                    'vulnerabilities': r.total_vulnerabilities
                }
                for r in reports
            ]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Database Routes ====================

@app.route('/api/database/test-results', methods=['POST'])
@token_required
@role_required('tester')
def save_test_result(payload):
    """Save test result to database"""
    data = request.json
    
    try:
        db = next(get_db())
        user_id = payload.get('user_id')
        
        test_result = TestResult(
            user_id=user_id,
            test_type=data.get('test_type'),
            target=data.get('target'),
            status=data.get('status', 'completed'),
            result=data.get('result'),
            vulnerabilities_found=data.get('vulnerabilities_found', 0),
            severity=data.get('severity', 'LOW'),
            notes=data.get('notes')
        )
        
        db.add(test_result)
        db.commit()
        
        return jsonify({'id': test_result.id, 'message': 'Test result saved'}), 201
    except Exception as e:
        logger.error(f"Error saving test result: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/database/audit-logs', methods=['GET'])
@token_required
@role_required('admin')
def get_audit_logs(payload):
    """Get audit logs"""
    try:
        db = next(get_db())
        limit = request.args.get('limit', 100, type=int)
        
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            'logs': [
                {
                    'id': l.id,
                    'action': l.action,
                    'resource': l.resource,
                    'status': l.status,
                    'timestamp': l.timestamp.isoformat(),
                    'ip_address': l.ip_address
                }
                for l in logs
            ]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Alert Routes ====================

@app.route('/api/alerts/threat', methods=['GET'])
def get_threat_alerts():
    """Get recent threat alerts"""
    limit = request.args.get('limit', 50, type=int)
    alerts = threat_alert_handler.get_alerts(limit)
    return jsonify({'alerts': alerts}), 200


@app.route('/api/alerts/security', methods=['GET'])
def get_security_alerts():
    """Get recent security test alerts"""
    limit = request.args.get('limit', 50, type=int)
    alerts = security_alert_handler.get_alerts(limit)
    return jsonify({'alerts': alerts}), 200


# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting VPN Proxy + Pentesting Toolkit Backend")
    
    # Get configuration from environment
    ssl_enabled = os.getenv('SSL_ENABLED', 'False').lower() == 'true'
    ssl_cert = os.getenv('SSL_CERT_PATH', './certs/server.crt')
    ssl_key = os.getenv('SSL_KEY_PATH', './certs/server.key')
    server_host = os.getenv('SERVER_HOST', '0.0.0.0')
    server_port = int(os.getenv('SERVER_PORT', '5000'))
    
    # Prepare SSL context if enabled
    ssl_context = None
    protocol = 'https' if ssl_enabled else 'http'
    
    if ssl_enabled:
        try:
            import ssl
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(ssl_cert, ssl_key)
            logger.info(f"SSL/TLS enabled with cert: {ssl_cert}")
        except Exception as e:
            logger.warning(f"Failed to load SSL certificates: {e}")
            logger.warning("Running without SSL/TLS")
            ssl_context = None
    
    logger.info(f"Server running on {protocol}://{server_host}:{server_port}")
    
    # Run server with SSL if configured
    if ssl_context:
        app.run(host=server_host, port=server_port, debug=False, ssl_context=ssl_context)
    else:
        app.run(host=server_host, port=server_port, debug=False)
