# SSL/TLS Certificates Directory

This directory contains SSL/TLS certificates for HTTPS support.

## Quick Start

### Generate Self-Signed Certificates

Run the certificate generation script:

```bash
python ../generate_certificates.py
```

Or manually with OpenSSL:

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate (valid for 365 days)
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Set proper permissions
chmod 600 server.key
chmod 644 server.crt
```

## File Structure

```
certs/
├── server.crt       # Certificate file (public)
├── server.key       # Private key (keep secure!)
└── README.md        # This file
```

## Security

⚠️ **IMPORTANT:**
- Never commit `server.key` to version control
- Never share your private key
- Keep `server.key` with 600 permissions
- Use production-grade certificates (Let's Encrypt) for real deployments

## Configuration

To enable SSL/TLS in the application:

1. **Update `backend/.env`:**
   ```
   SSL_ENABLED=True
   SSL_CERT_PATH=./certs/server.crt
   SSL_KEY_PATH=./certs/server.key
   ```

2. **Restart the server:**
   ```bash
   # Docker
   docker-compose restart backend
   
   # Or native Python
   python server.py
   ```

3. **Access via HTTPS:**
   ```bash
   curl https://localhost:5000/api/health --insecure
   ```

## Certificate Types

### Self-Signed (Development)
- Generated locally
- No trusted CA
- Browser warnings (expected)
- Perfect for testing
- Valid for 365 days

### Let's Encrypt (Production)
- Free, industry-standard
- Auto-renewal available
- Trusted by all browsers
- Requires domain name
- Installation: Use Certbot

### Custom CA (Enterprise)
- Sign with internal CA
- Trusted within organization
- Requires internal infrastructure

## Testing HTTPS

### Test with curl

```bash
# Ignore certificate warnings (development only)
curl https://localhost:5000/api/health --insecure

# With verbose output
curl -v https://localhost:5000/api/health --insecure

# Show certificate info
curl --cert-status https://localhost:5000/api/health --insecure
```

### Test with Python

```python
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

response = requests.get('https://localhost:5000/api/health', verify=False)
print(response.status_code)
```

### Test with OpenSSL

```bash
# Test certificate validity
openssl x509 -in server.crt -text -noout

# Test connection
openssl s_client -connect localhost:5000 -cert server.crt -key server.key

# Check expiration date
openssl x509 -enddate -noout -in server.crt
```

## Troubleshooting

### Certificate Expired
```bash
# Check expiration
openssl x509 -enddate -noout -in server.crt

# Regenerate certificate
python ../generate_certificates.py --days 365
```

### Wrong Hostname
```bash
# Regenerate with correct hostname
python ../generate_certificates.py --hostname your-domain.com
```

### Permission Denied
```bash
# Fix permissions
chmod 600 server.key
chmod 644 server.crt
```

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000

# Kill if necessary
kill -9 <PID>
```

## Production Deployment

For production, use Let's Encrypt certificates:

```bash
# Install Certbot
sudo apt-get install certbot

# Generate certificate for your domain
sudo certbot certonly --standalone -d your-domain.com

# Copy to certs directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem server.key
sudo chown $USER:$USER server.*
sudo chmod 600 server.key
chmod 644 server.crt

# Auto-renewal is set up automatically by Certbot
```

## Certificate Details

### Self-Signed
- **Validity:** 365 days
- **Key Size:** 2048 bits (RSA)
- **Hash:** SHA256
- **Format:** PEM

### Let's Encrypt
- **Validity:** 90 days
- **Key Size:** 2048 bits (RSA)
- **Hash:** SHA256
- **Auto-renewal:** Every 60 days

## References

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Let's Encrypt](https://letsencrypt.org/)
- [Certbot Documentation](https://certbot.eff.org/)
- [OWASP - Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
