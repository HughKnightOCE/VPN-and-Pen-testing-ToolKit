# VPN Proxy + Pentesting Toolkit - Architecture & Technical Details

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    REACT FRONTEND (5173)                      │
│  ┌──────────────┬──────────────┬──────────────┬────────────┐ │
│  │   VPN Panel  │Traffic Monitor│Pentest Tools │ Settings  │ │
│  └──────────────┴──────────────┴──────────────┴────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/REST API
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  FLASK BACKEND (5000)                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              API Routes & Controllers                   │ │
│  ├──────────────┬──────────────┬──────────────────────────┤ │
│  │ VPN Routes   │ Traffic      │ Pentesting Routes       │ │
│  │ /api/vpn/*   │ /api/traffic │ /api/pentest/*          │ │
│  └──────────────┴──────────────┴──────────────────────────┘ │
│                           │                                   │
│  ┌────────────────────────┴────────────────────────────────┐ │
│  │           Core Components                               │ │
│  ├─────────────┬──────────────┬──────────────────────────┤ │
│  │ SOCKS5      │ Encryption   │ DNS Handler            │ │
│  │ Proxy       │ (AES-256)    │ (Leak Prevention)      │ │
│  └─────────────┴──────────────┴──────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           Pentesting Modules                            │ │
│  ├─────────────┬──────────────┬──────────────────────────┤ │
│  │ SQL Tester  │ XSS Tester   │ Port Scanner           │ │
│  ├─────────────┬──────────────┬──────────────────────────┤ │
│  │ Cert        │ Interceptor  │ Traffic Analyzer       │ │
│  │ Analyzer    │              │                         │ │
│  └─────────────┴──────────────┴──────────────────────────┘ │
│                           │                                   │
│  ┌────────────────────────┴────────────────────────────────┐ │
│  │        Network & External Services                       │ │
│  ├────────────────┬──────────────┬────────────────────────┤ │
│  │ Socket Layer   │ DNS Servers  │ HTTP/HTTPS Targets   │ │
│  └────────────────┴──────────────┴────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔌 Core Components

### 1. SOCKS5 Proxy Server (`proxy.py`)
**Purpose**: Acts as intermediary for client connections

**Features**:
- Listens on `127.0.0.1:9050`
- Handles SOCKS5 protocol handshake
- Supports IPv4, IPv6, and domain names
- Bidirectional traffic relay
- Integration with encryption & DNS handlers
- Connection tracking & statistics

**Key Methods**:
```python
run()                  # Start proxy server
handle_client()        # Process individual connections
socks5_handshake()     # SOCKS5 auth negotiation
process_request()      # Parse SOCKS5 commands
relay_traffic()        # Forward encrypted data
```

**Security**:
- Encrypted traffic relay
- DNS resolution logging
- Connection rate tracking

---

### 2. Encryption Manager (`encryption.py`)
**Purpose**: Handles AES-256 encryption/decryption

**Features**:
- AES-256-CBC mode
- Random IV for each message
- PKCS7 padding
- SHA256-based key derivation
- Password-based key management

**Key Methods**:
```python
encrypt(plaintext)     # Encrypt data
decrypt(ciphertext)    # Decrypt data
derive_key(password)   # Generate encryption key
pad(data)              # Add PKCS7 padding
unpad(data)            # Remove PKCS7 padding
```

**Security Details**:
- IV: 16 random bytes (prepended to ciphertext)
- Key: 256-bit derived from password
- Iterations: 100,000 SHA256 rounds
- Mode: CBC with PKCS7 padding

**Usage**:
```python
manager = EncryptionManager()
encrypted = manager.encrypt(b"data")
decrypted = manager.decrypt(encrypted)
```

---

### 3. DNS Handler (`dns_handler.py`)
**Purpose**: Prevents DNS leaks and ensures secure resolution

**Features**:
- Secure DNS servers (Cloudflare, Google)
- DNS caching
- Leak detection
- Fallback resolution

**Secure DNS Servers**:
- `1.1.1.1` - Cloudflare (Primary)
- `1.0.0.1` - Cloudflare (Secondary)
- `8.8.8.8` - Google (Primary)
- `8.8.4.4` - Google (Secondary)

**Key Methods**:
```python
resolve(hostname)           # Resolve with secure DNS
test_for_leaks()           # Check for DNS leaks
flush_cache()              # Clear DNS cache
get_cache_stats()          # Cache statistics
```

**Leak Detection**:
- Tests against public DNS leak sites
- Verifies responses use secure servers only
- Logs any unauthorized DNS queries

---

### 4. Traffic Analyzer (`traffic_analyzer.py`)
**Purpose**: Monitors and logs all network traffic

**Features**:
- Real-time packet tracking
- Connection statistics
- Traffic history (max 1000 packets)
- Per-host/port breakdown
- Bandwidth calculation

**Key Methods**:
```python
log_send(bytes, host, port)    # Log outgoing traffic
log_receive(bytes, host, port) # Log incoming traffic
get_stats()                    # Get statistics
get_history(limit)             # Get packet history
clear_history()                # Clear logs
```

**Tracked Data**:
- Timestamp of each packet
- Source/destination host
- Port number
- Direction (send/receive)
- Bytes transferred
- Packet count per connection

---

## 🔨 Pentesting Modules

### 1. SQL Injection Tester (`sql_tester.py`)
**Purpose**: Detects SQL injection vulnerabilities

**Methodology**:
- Tests common SQL injection payloads
- Analyzes URL parameters
- Checks for SQL error messages
- Identifies vulnerable parameters

**Payloads Tested**:
```python
"' OR '1'='1"
"' OR 1=1 --"
"' OR 1=1 #"
"admin' --"
"1' UNION SELECT NULL --"
```

**Error Detection**:
- MySQL errors
- PostgreSQL errors
- ORACLE errors
- Generic SQL syntax errors

**Usage**:
```python
tester = SQLTester()
results = tester.test_url("http://target.com/page?id=1")
# Returns: {vulnerable, vulnerable_params, results}
```

---

### 2. XSS Tester (`xss_tester.py`)
**Purpose**: Identifies Cross-Site Scripting vulnerabilities

**Methodology**:
- Injects XSS payloads into parameters
- Checks for payload reflection
- Detects both raw and HTML-encoded responses
- Identifies vulnerable input fields

**Payloads Tested**:
```python
"<script>alert('XSS')</script>"
"<img src=x onerror='alert(1)'>"
"<svg onload='alert(1)'>"
"javascript:alert(1)"
```

**Detection Methods**:
- Exact payload match
- HTML entity encoding detection
- Event handler patterns

**Usage**:
```python
tester = XSSTester()
results = tester.test_url("http://target.com/search?q=test")
```

---

### 3. Port Scanner (`port_scanner.py`)
**Purpose**: Identifies open ports and services

**Methodology**:
- Socket-based port scanning
- Connection timeout approach
- Service identification
- Fast, efficient scanning

**Features**:
- Scans custom port ranges
- Identifies common services
- Handles domain resolution
- Graceful error handling

**Service Mapping**:
```python
21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS'
3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP'
```

**Usage**:
```python
scanner = PortScanner()
results = scanner.scan("example.com", "1-1000")
# Returns: {open_ports, services, closed_ports}
```

**Timeout**: 1 second per port (configurable)

---

### 4. Certificate Analyzer (`cert_analyzer.py`)
**Purpose**: Analyzes SSL/TLS certificate security

**Features**:
- Retrieves certificate from server
- Extracts certificate metadata
- Detects security issues
- Checks expiration dates

**Information Extracted**:
- Subject (CN)
- Issuer
- Validity dates
- Subject Alternative Names
- Serial number
- Signature algorithm

**Vulnerabilities Detected**:
- Expired certificates
- Certificates expiring soon (< 30 days)
- Weak signature algorithms (MD5, SHA1)
- Self-signed certificates

**Usage**:
```python
analyzer = CertificateAnalyzer()
results = analyzer.analyze("google.com", 443)
```

---

### 5. Request Interceptor (`interceptor.py`)
**Purpose**: Captures and logs HTTP/HTTPS requests

**Features**:
- Request logging (up to 500 requests)
- Request modification capability
- URL-based filtering
- Request history management

**Logged Data**:
- Timestamp
- HTTP method (GET, POST, etc.)
- Full URL
- Headers
- Request body
- Response status code

**Usage**:
```python
interceptor = RequestInterceptor()
interceptor.start()
# Requests are logged automatically
interceptor.log_request("POST", "http://api.example.com/login", headers)
```

---

## 🖥️ Frontend Components

### 1. VPNControl.jsx
**Features**:
- Large toggle button for VPN on/off
- Kill switch toggle
- DNS leak testing
- Feature status cards
- Real-time status display

**State Management**:
```javascript
vpnActive          // Boolean - VPN running status
killSwitch         // Boolean - Kill switch enabled
dnsLeakTest        // Object - DNS leak test results
loading, error     // UI state
```

### 2. TrafficMonitor.jsx
**Features**:
- Real-time traffic statistics
- Bandwidth graphs (Recharts)
- Active connections table
- Traffic history export
- Clear history function

**Metrics Displayed**:
- Bytes sent/received
- Total data transferred
- Active connection count
- Packets sent
- Per-connection breakdown

### 3. PentestTools.jsx
**Features**:
- Tabbed interface for 4 tools
- URL/host input fields
- Real-time test results
- JSON result display
- Vulnerability badges

**Tools Available**:
1. SQL Injection Tester
2. XSS Vulnerability Tester
3. Port Scanner
4. Certificate Analyzer

### 4. Settings.jsx
**Features**:
- Configuration display
- Security information
- System information
- Documentation links
- Security warnings

---

## 📡 API Architecture

### Request/Response Format

**Standard Request**:
```json
{
  "method": "POST",
  "endpoint": "/api/pentest/sql-injection",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": {
    "url": "http://target.com/page?id=1"
  }
}
```

**Standard Response**:
```json
{
  "status": 200,
  "data": {
    "vulnerable": true,
    "vulnerable_params": ["id"],
    "results": [...]
  }
}
```

**Error Response**:
```json
{
  "status": 400,
  "error": "URL required"
}
```

---

## 🔒 Security Architecture

### Encryption Flow
```
User Input
    ↓
Plaintext Data
    ↓
+ Random IV (16 bytes)
    ↓
AES-256-CBC Encryption
    ↓
IV + Ciphertext (output)
```

### Decryption Flow
```
IV + Ciphertext (input)
    ↓
Extract IV (first 16 bytes)
    ↓
AES-256-CBC Decryption
    ↓
Remove PKCS7 Padding
    ↓
Plaintext Data
```

### DNS Security
```
DNS Query
    ↓
Use Secure Server (Cloudflare/Google)
    ↓
Cache Result
    ↓
Return IP
    ↓
Compare with System DNS (Leak Detection)
```

---

## ⚡ Performance Characteristics

### Proxy Performance
- Connection handling: Multi-threaded
- Buffer size: 4096 bytes per relay
- Timeout: 1 second per select() call
- Maximum concurrent connections: Limited by OS

### Encryption Performance
- AES-256-CBC: Hardware accelerated (if available)
- Key derivation: ~100ms per password
- Encryption overhead: ~10-15% bandwidth increase

### Scanning Performance
- Port scanning: ~500ms per port (with 1s timeout)
- Certificate analysis: 2-5 seconds per host
- SQL/XSS testing: Varies by target response time

---

## 🚀 Deployment Notes

### Development
- Flask debug mode disabled
- Single-threaded frontend (Vite dev server)
- Local-only communication

### Production Recommendations
1. Use Gunicorn/Waitress for Flask
2. Implement reverse proxy (Nginx)
3. Add SSL/TLS certificates
4. Enable authentication & authorization
5. Implement rate limiting
6. Add comprehensive logging
7. Deploy on secure infrastructure
8. Regular security audits

---

## 📊 Data Flow Diagram

```
USER REQUEST
    ↓
FRONTEND (React)
    ↓
[HTTP/REST API]
    ↓
FLASK ROUTING
    ↓
    ├─→ VPN Routes
    │   ├→ Proxy ←→ SOCKS5 Server
    │   ├→ Encryption Manager
    │   └→ DNS Handler
    ├─→ Traffic Routes
    │   └→ Traffic Analyzer
    └─→ Pentest Routes
        ├→ SQL Tester
        ├→ XSS Tester
        ├→ Port Scanner
        ├→ Cert Analyzer
        └→ Interceptor
    ↓
[RETURN RESULTS]
    ↓
FRONTEND (Update UI)
    ↓
USER SEES RESULTS
```

---

This architecture ensures:
- ✅ Modular design
- ✅ Secure communication
- ✅ Easy maintenance
- ✅ Scalable structure
- ✅ Clear separation of concerns
