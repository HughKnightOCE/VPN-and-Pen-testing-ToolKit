# Docker Deployment Guide

This guide covers how to deploy the VPN Proxy + Pentesting Toolkit using Docker and Docker Compose.

## Quick Start

### Prerequisites
- Docker installed (https://docs.docker.com/get-docker/)
- Docker Compose installed (included with Docker Desktop)
- Git clone of this repository

### Deploy with One Command

```bash
cd /path/to/VPN-Pentesting-Toolkit
docker-compose up -d
```

That's it! The application will be available at:
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000
- **SOCKS5 Proxy**: 127.0.0.1:9050

### Stop the Application

```bash
docker-compose down
```

### View Logs

```bash
# All logs
docker-compose logs -f

# Backend only
docker-compose logs -f backend

# Frontend only
docker-compose logs -f frontend
```

## Configuration

### Using Environment Variables

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` with your settings:
```
FLASK_ENV=production
PROXY_PORT=9050
PROXY_ENCRYPTION_PASSWORD=your-secure-password
AUTO_BLOCK_MALICIOUS_IPS=false
```

3. Restart containers:
```bash
docker-compose up -d
```

### Available Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | production | Flask environment |
| `FLASK_PORT` | 5000 | Backend API port |
| `PROXY_HOST` | 0.0.0.0 | Proxy listening address |
| `PROXY_PORT` | 9050 | SOCKS5 proxy port |
| `PROXY_ENCRYPTION_PASSWORD` | changeme | Encryption password |
| `PRIMARY_DNS` | 1.1.1.1 | Primary DNS server |
| `SECONDARY_DNS` | 8.8.8.8 | Secondary DNS server |
| `LOG_LEVEL` | INFO | Logging level |
| `THREAT_DETECTION_ENABLED` | true | Enable threat detection |
| `AUTO_BLOCK_MALICIOUS_IPS` | false | Auto-block detected threats |

## Docker Images

### Backend Image (Python Flask)
- **Base**: python:3.11-slim
- **Size**: ~350MB
- **Includes**: Flask, cryptography, dnspython, requests
- **Port**: 5000, 9050
- **Health Check**: Every 30 seconds via `/api/health`

### Frontend Image (React + Nginx)
- **Base**: Node 18 Alpine + Nginx Alpine
- **Build**: Vite production build
- **Size**: ~100MB
- **Port**: 5173
- **Health Check**: Every 30 seconds via HTTP

## Volumes and Persistence

The Docker setup includes persistent storage for:
- **Data volume** (`./data`): Stores database, logs, and configuration
- **Backend code** (`./backend`): Source code volume
- **Frontend code** (`./frontend`): Source code volume

Files are persisted even after containers are stopped:
```bash
docker-compose down  # Containers stop, data persists
docker-compose up -d  # Restart with all previous data intact
```

To completely remove persistent data:
```bash
docker-compose down -v  # -v flag removes volumes
```

## Networking

Containers communicate over a custom Docker network (`vpn-network`) on bridge driver.

- **Backend service**: Accessible at `http://backend:5000` from frontend container
- **Frontend service**: Accessible at `http://frontend:5173` from backend container
- **External access**: Via localhost ports (5000, 5173, 9050)

## Production Deployment

For production environments, follow these best practices:

### 1. Security

```bash
# Change default encryption password
PROXY_ENCRYPTION_PASSWORD=your-very-strong-password-here

# Use a reverse proxy (Nginx)
# Use HTTPS/SSL certificates
# Set FLASK_ENV=production
# Disable debug mode
```

### 2. Scaling

For multiple users, increase resources:
```yaml
# In docker-compose.yml
backend:
  environment:
    PROXY_MAX_CONNECTIONS: 1000
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 2G
```

### 3. Monitoring

Add health checks and monitoring:
```bash
docker stats  # View resource usage

docker-compose logs --tail=100 backend  # Last 100 logs
```

### 4. Database

For production, use PostgreSQL instead of SQLite:

1. Add PostgreSQL service to docker-compose.yml:
```yaml
postgres:
  image: postgres:15-alpine
  environment:
    POSTGRES_USER: vpn_user
    POSTGRES_PASSWORD: secure_password
    POSTGRES_DB: vpn_toolkit
  volumes:
    - postgres_data:/var/lib/postgresql/data
```

2. Update `.env`:
```
DATABASE_URL=postgresql://vpn_user:secure_password@postgres:5432/vpn_toolkit
```

3. Restart:
```bash
docker-compose up -d
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs backend

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d
```

### Port already in use

Change ports in docker-compose.yml or stop conflicting services:
```bash
# Find what's using port 5000
lsof -i :5000

# Or change ports in docker-compose.yml
ports:
  - "5001:5000"  # Change first number (external port)
```

### Slow performance

- Check Docker resource allocation
- View logs for errors
- Ensure adequate CPU/memory available

```bash
docker stats  # Check resource usage
```

### Database corruption

Backup and reset:
```bash
# Backup data
cp -r data data.backup

# Remove and recreate
docker-compose down -v
docker-compose up -d
```

## Advanced Configuration

### Custom Docker Networks

Create a shared network for multiple projects:
```bash
docker network create vpn-network
docker-compose --network=vpn-network up -d
```

### Docker Compose Overrides

For development, create `docker-compose.override.yml`:
```yaml
version: '3.9'
services:
  backend:
    environment:
      FLASK_ENV: development
      LOG_LEVEL: DEBUG
    ports:
      - "5000:5000"
```

### Building Images Manually

```bash
# Build backend image
docker build -t vpn-toolkit-backend:latest backend/

# Build frontend image
docker build -t vpn-toolkit-frontend:latest frontend/

# Run manually
docker run -p 5000:5000 vpn-toolkit-backend:latest
docker run -p 5173:5173 vpn-toolkit-frontend:latest
```

## CI/CD Integration

See `.github/workflows/docker-build.yml` for automated building and testing on git push.

To push to Docker Hub:
```bash
docker tag vpn-toolkit-backend:latest yourusername/vpn-toolkit-backend:latest
docker push yourusername/vpn-toolkit-backend:latest
```

## Performance Optimization

### For Throughput

```yaml
backend:
  environment:
    PROXY_MAX_CONNECTIONS: 5000
  deploy:
    resources:
      limits:
        cpus: '4'
        memory: 4G
```

### For Low Latency

- Use `--network=host` on Linux (not recommended for security)
- Reduce encryption complexity (AES-128 instead of AES-256)
- Disable traffic logging

```yaml
backend:
  environment:
    LOG_LEVEL: WARNING
    TRAFFIC_LOGGING_ENABLED: "false"
```

## Support

For issues with Docker deployment:
1. Check logs: `docker-compose logs`
2. Rebuild: `docker-compose build --no-cache`
3. Reset: `docker-compose down -v && docker-compose up -d`

---

**Last Updated**: February 5, 2026
