# VPN Proxy + Pentesting Toolkit

A production-grade VPN proxy server with integrated penetration testing tools and a modern React GUI.

## What is This?

This toolkit is a **complete cybersecurity solution** that combines three critical capabilities:

1. **VPN Proxy Server** - A local SOCKS5 proxy that encrypts and routes all network traffic through an encrypted tunnel with AES-256 encryption. Think of it as a personal VPN that runs on your machine with full control and visibility.

2. **Pentesting Toolkit** - A collection of security testing tools built directly into the application. Test websites for SQL injection vulnerabilities, XSS flaws, scan for open ports, analyze SSL certificates, and capture/analyze HTTP requests—all from one interface.

3. **Traffic Monitoring Dashboard** - Real-time visibility into all network activity flowing through the proxy. See exactly what data is being sent, where it's going, connection speeds, and patterns.

## Why I Built This

**Problem:** Existing pentesting tools are fragmented—you need nmap for port scanning, Burp Suite for request interception, separate VPN software, and various command-line utilities. Managing all these tools is complex and time-consuming.

**Solution:** This toolkit unifies everything into one modern, professional application with:
- 🔒 **Integrated security** - Encryption built-in from the start, not bolted on
- 🎯 **All-in-one interface** - No context switching between 10 different tools
- ⚡ **Real-time feedback** - See results instantly with live charts and metrics
- 🏗️ **Production quality** - Enterprise-grade architecture, not a hobby project
- 🔧 **Extensible** - Easy to add new pentesting modules or customize for your needs

**Use Cases:**
- Security researchers conducting authorized penetration tests
- System administrators testing their infrastructure security
- Developers learning about web vulnerabilities and network security
- Red team operations requiring a unified testing platform
- Security audits with detailed reporting and logging

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

## Verifying the Proxy Works

### Method 1: Check Traffic Monitor (Easiest)
1. Open `http://localhost:5173`
2. Click "VPN ON" in the VPN Control tab
3. Open a new tab and visit any website
4. Switch to "Traffic Monitor" tab
5. ✅ You should see live traffic data (packets sent/received)

### Method 2: Test with cURL
```powershell
# Test without proxy (normal)
curl -v http://example.com

# Test WITH proxy
curl --socks5 127.0.0.1:9050 -v http://example.com

# Compare the response times - proxy adds slight latency due to encryption
```

### Method 3: Verify Encryption is Working
1. Start the proxy (VPN ON)
2. Go to "Traffic Monitor" tab
3. You'll see encrypted traffic data flowing through
4. Open browser DevTools Network tab and compare:
   - Direct connection shows plain URLs in logs
   - Through proxy, traffic is encrypted (you'll see the bytes in motion)

### Method 4: DNS Leak Test
1. Click "Test DNS Leak" in VPN Control
2. ✅ If working properly, DNS queries go through Cloudflare/Google (not your ISP)
3. Check the response - should show Cloudflare or Google DNS, not your ISP

### Method 5: Network Analysis
1. Click "VPN ON"
2. Browse normally
3. Check "Traffic Monitor" - you should see:
   - **Sent/Received bytes** increasing
   - **Active connections** showing which domains you're connected to
   - **Packets flowing** in the live graph
   - Connection list with bytes per host

### How to Know It's REALLY Working
✅ **Signs the proxy is legitimate:**
- Browser loads pages at normal speed (slight lag is normal due to encryption)
- Traffic Monitor shows consistent data flow
- DNS leak test passes
- Encrypted bytes accumulate as you browse
- No errors in backend console

⚠️ **If something's wrong:**
- Traffic Monitor shows 0 bytes → Proxy not intercepting traffic
- DNS leak test fails → DNS not routing through proxy
- Backend shows connection errors → Port 9050 might be blocked
- Browser can't load pages → Check proxy configuration

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
