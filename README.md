# VPN Proxy + Pentesting Toolkit

A production-grade VPN proxy server with integrated penetration testing tools and a modern React GUI.

## Features

### VPN Proxy Component
- SOCKS5 proxy server with traffic encryption
- AES-256 encryption for all traffic
- DNS leak prevention
- Kill switch functionality
- IP masking and traffic routing
- Real-time connection monitoring

### Pentesting Toolkit
- Request interceptor/modifier (MITM-style)
- SQL injection vulnerability tester
- XSS payload generator and detector
- Port scanner with service detection
- SSL/TLS certificate analyzer
- Network traffic analyzer
- Threat detection engine

### GUI Dashboard
- VPN control panel with status indicators
- Real-time traffic monitoring
- Pentesting tool interface
- Network statistics and analytics
- Connection history and logs
- Settings and configuration management

## Requirements

- Python 3.9+
- Node.js 16+
- Windows 10+ / Linux / macOS

## Quick Start

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python server.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Access GUI at `http://localhost:5173`

## Architecture

```
backend/
  ├── proxy.py           # SOCKS5 proxy server
  ├── encryption.py      # AES-256 encryption
  ├── dns_handler.py     # DNS leak prevention
  ├── traffic_analyzer.py # Network analysis
  └── pentesting/
      ├── sql_tester.py
      ├── xss_tester.py
      ├── port_scanner.py
      ├── cert_analyzer.py
      └── interceptor.py

frontend/
  └── src/
      ├── components/
      │   ├── VPNControl.jsx
      │   ├── TrafficMonitor.jsx
      │   ├── PentestTools.jsx
      │   └── Settings.jsx
      └── App.jsx
```

## Security Notice

⚠️ **This tool is for authorized security testing only.** Unauthorized access to computer systems is illegal. Always obtain proper authorization before performing security audits or penetration testing.

## License

MIT
