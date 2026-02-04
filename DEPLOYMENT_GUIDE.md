# VPN Proxy + Pentesting Toolkit - Deployment Guide

## Table of Contents
1. [Local Development Setup](#local-development-setup)
2. [Docker Deployment](#docker-deployment)
3. [Production Deployment](#production-deployment)
4. [Configuration](#configuration)
5. [SSL/TLS Setup](#ssltls-setup)
6. [Email Alerts](#email-alerts)
7. [Slack Alerts](#slack-alerts)
8. [Troubleshooting](#troubleshooting)

---

## Local Development Setup

### Prerequisites
- Python 3.11+
- pip (Python package manager)
- Git

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/HughKnightOCE/VPN-and-Pen-testing-ToolKit.git
   cd VPN-and-Pentesting-Toolkit
   ```

2. **Navigate to backend directory**
   ```bash
   cd backend
   ```

3. **Create Python virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # Activate virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Configure environment variables**
   ```bash
   # Copy the example .env file
   cp .env.example .env
   
   # Edit .env with your settings
   # For development, most defaults are fine
   ```

6. **Start the backend server**
   ```bash
   python server.py
   ```
   
   Server will run on `http://localhost:5000`

7. **Start the frontend** (in a new terminal)
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   
   Frontend will run on `http://localhost:5173`

---

## Docker Deployment

### Prerequisites
- Docker installed
- Docker Compose installed

### Quick Start

1. **Navigate to project root**
   ```bash
   cd VPN-and-Pentesting-Toolkit
   ```

2. **Configure environment** (optional)
   ```bash
   # Edit backend/.env if needed (already has sensible defaults)
   ```

3. **Build and start containers**
   ```bash
   docker-compose up -d
   ```

4. **Check status**
   ```bash
   docker-compose ps
   ```

5. **Access services**
   - Backend API: http://localhost:5000
   - Frontend: http://localhost:5173

6. **View logs**
   ```bash
   # Backend logs
   docker-compose logs -f backend
   
   # Frontend logs
   docker-compose logs -f frontend
   
   # All logs
   docker-compose logs -f
   ```

7. **Stop containers**
   ```bash
   docker-compose down
   ```

### Docker Commands

**Rebuild containers after code changes:**
```bash
docker-compose up -d --build
```

**Remove all containers and volumes:**
```bash
docker-compose down -v
```

**Run commands inside container:**
```bash
# Access backend shell
docker-compose exec backend bash

# Run Python command
docker-compose exec backend python -c "print('Hello')"
```

---

## Production Deployment

### Server Requirements
- Linux (Ubuntu 20.04+ recommended)
- 2+ CPU cores
- 2GB+ RAM
- 10GB+ disk space
- Outbound internet access for Slack/email

### Step 1: Server Setup

1. **Update system**
   ```bash
   sudo apt-get update
   sudo apt-get upgrade -y
   ```

2. **Install Docker and Docker Compose**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

3. **Create application directory**
   ```bash
   sudo mkdir -p /opt/vpn-toolkit
   sudo chown $USER:$USER /opt/vpn-toolkit
   ```

4. **Clone repository**
   ```bash
   cd /opt/vpn-toolkit
   git clone https://github.com/HughKnightOCE/VPN-and-Pen-testing-ToolKit.git .
   ```

### Step 2: Configure for Production

1. **Set up .env file**
   ```bash
   cp backend/.env.example backend/.env
   nano backend/.env
   ```
   
   **Critical changes:**
   - Change `FLASK_ENV=production`
   - Change `FLASK_DEBUG=False`
   - Change `SECRET_KEY` to a random 32+ character string
   - Change `JWT_SECRET` to a random string
   - Enable `SSL_ENABLED=True` (after certificates are ready)
   - Configure email/Slack if needed

2. **Generate new SECRET_KEY**
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Create data directories**
   ```bash
   mkdir -p data logs certs
   chmod 700 certs
   ```

### Step 3: Setup SSL/TLS (recommended)

See [SSL/TLS Setup](#ssltls-setup) section below.

### Step 4: Start Services

```bash
docker-compose up -d
```

### Step 5: Verify Installation

```bash
# Check container status
docker-compose ps

# Check backend health
curl http://localhost:5000/api/health

# Check logs for errors
docker-compose logs backend
```

### Step 6: Reverse Proxy Setup (Nginx)

Create `/etc/nginx/sites-available/vpn-toolkit`:

```nginx
upstream backend {
    server localhost:5000;
}

upstream frontend {
    server localhost:5173;
}

server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL certificates (set up with Certbot)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    
    # API requests to backend
    location /api/ {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Frontend
    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/vpn-toolkit /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: Setup SSL with Certbot

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot certonly --nginx -d your-domain.com
```

---

## Configuration

### Environment Variables

All configuration is managed through `.env` file in the `backend/` directory:

#### Flask Settings
```
FLASK_ENV=production          # development or production
FLASK_DEBUG=False             # Disable debug mode in production
SECRET_KEY=your-secret        # Flask secret key
SERVER_HOST=0.0.0.0          # Bind to all interfaces
SERVER_PORT=5000             # API port
```

#### Database
```
DATABASE_URL=sqlite:///vpn_toolkit.db   # SQLite database path
SQLALCHEMY_TRACK_MODIFICATIONS=False
```

#### Authentication
```
JWT_SECRET=your-jwt-secret    # JWT signing secret
JWT_EXPIRATION_HOURS=24       # Token expiration time
```

#### Rate Limiting
```
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST=100
```

#### Threat Detection
```
THREAT_DETECTION_ENABLED=True
PORT_SCAN_THRESHOLD=10
BRUTE_FORCE_THRESHOLD=5
DDOS_THRESHOLD=100
```

#### SSL/TLS
```
SSL_ENABLED=False             # Set to True for HTTPS
SSL_CERT_PATH=./certs/server.crt
SSL_KEY_PATH=./certs/server.key
```

---

## SSL/TLS Setup

### Option 1: Self-Signed Certificates (Development)

```bash
cd backend/certs

# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate (valid for 365 days)
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Copy to production location if needed
# chmod 600 server.key server.crt
```

### Option 2: Let's Encrypt Certificates (Production)

```bash
# Install Certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy to application directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem backend/certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem backend/certs/server.key
sudo chown $USER:$USER backend/certs/*
sudo chmod 600 backend/certs/server.key
```

### Enable SSL in Application

1. **Update .env**
   ```
   SSL_ENABLED=True
   SSL_CERT_PATH=./certs/server.crt
   SSL_KEY_PATH=./certs/server.key
   ```

2. **Restart application**
   ```bash
   docker-compose restart backend
   ```

3. **Access via HTTPS**
   ```bash
   curl https://localhost:5000/api/health --insecure
   ```

---

## Email Alerts

### Gmail Setup

1. **Enable 2-Factor Authentication**
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification

2. **Generate App Password**
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" and "Windows Computer"
   - Copy the generated 16-character password

3. **Update .env**
   ```
   SMTP_ENABLED=True
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   SMTP_FROM_ADDRESS=alerts@vpn-toolkit.com
   ALERT_EMAIL_RECIPIENTS=admin@example.com,security@example.com
   ```

4. **Test Email**
   ```bash
   docker-compose exec backend python -c "
   from alert_handler import threat_alert_handler
   threat_alert_handler.alert_port_scan('192.168.1.1', '192.168.1.100', 5, {})
   "
   ```

### Office 365 Setup

```
SMTP_SERVER=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=your-email@company.com
SMTP_PASSWORD=your-password
```

### Custom SMTP Server

```
SMTP_SERVER=smtp.yourserver.com
SMTP_PORT=587
SMTP_USERNAME=username
SMTP_PASSWORD=password
```

---

## Slack Alerts

### Setup

1. **Create Slack App**
   - Go to https://api.slack.com/apps
   - Click "Create New App" → "From scratch"
   - Name: "VPN Toolkit Alerts"
   - Choose your workspace

2. **Enable Incoming Webhooks**
   - In left menu, click "Incoming Webhooks"
   - Click "Add New Webhook to Workspace"
   - Select channel (e.g., #security-alerts)
   - Copy the Webhook URL

3. **Update .env**
   ```
   SLACK_ENABLED=True
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   SLACK_CHANNEL=#security-alerts
   SLACK_USERNAME=VPN Toolkit Bot
   ```

4. **Test Slack**
   ```bash
   docker-compose exec backend python -c "
   from alert_handler import threat_alert_handler
   threat_alert_handler.alert_ddos('192.168.1.1', 1000000, {})
   "
   ```

---

## Monitoring and Maintenance

### Check Logs

```bash
# Last 50 lines of backend logs
docker-compose logs --tail=50 backend

# Follow logs in real-time
docker-compose logs -f backend

# Logs since specific time
docker-compose logs --since 2h backend
```

### Database Backups

```bash
# Backup database
docker cp vpn-toolkit-backend:/app/data/vpn_toolkit.db ./backup_$(date +%Y%m%d).db

# Restore database
docker cp ./backup_20260205.db vpn-toolkit-backend:/app/data/vpn_toolkit.db
docker-compose restart backend
```

### Update Application

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose up -d --build

# Check status
docker-compose ps
docker-compose logs backend
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs backend

# Check if port is already in use
lsof -i :5000

# Rebuild containers
docker-compose down -v
docker-compose up -d --build
```

### Port Already in Use

```bash
# Find process using port 5000
lsof -i :5000

# Kill process (if safe)
kill -9 <PID>

# Or use different port in docker-compose.yml
```

### Database Issues

```bash
# Reset database
docker-compose exec backend rm -f data/vpn_toolkit.db

# Restart backend
docker-compose restart backend
```

### Email Alerts Not Sending

1. Check SMTP credentials in .env
2. Enable "Less secure app access" (Gmail only)
3. Check logs: `docker-compose logs backend | grep -i email`
4. Test manually: `python -c "import smtplib; smtplib.SMTP('smtp.gmail.com', 587)"`

### Slack Alerts Not Sending

1. Verify webhook URL in .env
2. Check logs: `docker-compose logs backend | grep -i slack`
3. Test webhook: 
   ```bash
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"Test message"}' \
     https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```

### Permission Issues

```bash
# Fix permissions
sudo chown -R $USER:$USER /opt/vpn-toolkit
chmod -R 755 /opt/vpn-toolkit
chmod 600 backend/.env
```

---

## Performance Tuning

### Increase Rate Limit for Testing

```env
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
```

### Enable Caching

Nginx caching (in Nginx config):
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m;
proxy_cache my_cache;
```

### Database Optimization

```bash
docker-compose exec backend python -c "
import sqlite3
conn = sqlite3.connect('data/vpn_toolkit.db')
conn.execute('VACUUM')
conn.close()
"
```

---

## Security Checklist

- [ ] Change all default credentials
- [ ] Enable HTTPS/SSL with valid certificates
- [ ] Set strong SECRET_KEY and JWT_SECRET
- [ ] Enable firewall rules
- [ ] Set up fail2ban for brute force protection
- [ ] Enable rate limiting
- [ ] Configure email/Slack alerts
- [ ] Regular database backups
- [ ] Keep dependencies updated
- [ ] Monitor logs regularly
- [ ] Use strong passwords
- [ ] Restrict API access by IP if possible

---

## Support

For issues or questions:
1. Check logs: `docker-compose logs -f backend`
2. Review .env configuration
3. Check GitHub issues: https://github.com/HughKnightOCE/VPN-and-Pen-testing-ToolKit/issues
4. Contact support with full logs and configuration (without secrets)
