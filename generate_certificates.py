#!/usr/bin/env python3
"""
Generate self-signed SSL/TLS certificates for development/testing
This script creates a self-signed certificate valid for 365 days
"""

import os
import subprocess
import sys
from pathlib import Path

def generate_certificates(cert_dir='./certs', hostname='localhost', days=365):
    """Generate self-signed SSL certificate"""
    
    # Create certs directory if it doesn't exist
    cert_path = Path(cert_dir)
    cert_path.mkdir(exist_ok=True)
    
    key_file = cert_path / 'server.key'
    cert_file = cert_path / 'server.crt'
    
    # Check if certificates already exist
    if key_file.exists() and cert_file.exists():
        response = input(f"Certificates already exist in {cert_dir}. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Certificate generation cancelled.")
            return False
    
    # Try using openssl command (preferred method)
    try:
        print(f"Generating self-signed SSL certificate for {hostname}...")
        
        # Generate private key
        print(f"  Creating private key: {key_file}")
        subprocess.run([
            'openssl', 'genrsa',
            '-out', str(key_file),
            '2048'
        ], check=True, capture_output=True)
        
        # Generate certificate
        print(f"  Creating certificate: {cert_file}")
        subprocess.run([
            'openssl', 'req', '-new', '-x509',
            '-key', str(key_file),
            '-out', str(cert_file),
            '-days', str(days),
            '-subj', f'/C=US/ST=State/L=City/O=VPN Toolkit/CN={hostname}'
        ], check=True, capture_output=True)
        
        # Set proper permissions
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
        
        print("\n✓ SSL certificates generated successfully!")
        print(f"  Private key: {key_file}")
        print(f"  Certificate: {cert_file}")
        print(f"  Valid for: {days} days")
        print(f"  Hostname: {hostname}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error running openssl: {e}")
        print("\nFalling back to Python cryptography library...")
        
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timedelta
            import ipaddress
            
            print(f"  Generating private key...")
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Save private key
            with open(key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(key_file, 0o600)
            
            print(f"  Generating certificate...")
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VPN Toolkit"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName('*.localhost'),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Save certificate
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            os.chmod(cert_file, 0o644)
            
            print("\n✓ SSL certificates generated successfully!")
            print(f"  Private key: {key_file}")
            print(f"  Certificate: {cert_file}")
            print(f"  Valid for: {days} days")
            print(f"  Hostname: {hostname}")
            
            return True
            
        except ImportError:
            print("✗ cryptography library not found")
            print("\nPlease install openssl or cryptography:")
            print("  - Install OpenSSL: https://www.openssl.org/")
            print("  - Or install Python package: pip install cryptography")
            return False
        except Exception as e:
            print(f"✗ Error generating certificate: {e}")
            return False
    
    except FileNotFoundError:
        print("✗ openssl command not found")
        print("\nPlease install OpenSSL:")
        print("  Windows: https://slproweb.com/products/Win32OpenSSL.html")
        print("  macOS: brew install openssl")
        print("  Linux: sudo apt-get install openssl")
        return False


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate self-signed SSL/TLS certificates for VPN Toolkit'
    )
    parser.add_argument(
        '--cert-dir',
        default='./certs',
        help='Directory to store certificates (default: ./certs)'
    )
    parser.add_argument(
        '--hostname',
        default='localhost',
        help='Hostname for the certificate (default: localhost)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=365,
        help='Certificate validity in days (default: 365)'
    )
    
    args = parser.parse_args()
    
    # Generate certificates
    success = generate_certificates(
        cert_dir=args.cert_dir,
        hostname=args.hostname,
        days=args.days
    )
    
    if not success:
        print("\n⚠️  Certificate generation failed")
        print("Note: SSL/TLS is optional for development")
        print("You can still run the application without SSL certificates")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("Next steps:")
    print("="*60)
    print("1. Update backend/.env:")
    print("   SSL_ENABLED=True")
    print("   SSL_CERT_PATH=./certs/server.crt")
    print("   SSL_KEY_PATH=./certs/server.key")
    print("\n2. Restart the backend server:")
    print("   docker-compose restart backend")
    print("   (or manually restart if running natively)")
    print("\n3. Access via HTTPS:")
    print("   curl https://localhost:5000/api/health --insecure")
    print("="*60)


if __name__ == '__main__':
    main()
