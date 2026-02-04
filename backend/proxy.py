"""
SOCKS5 Proxy Server Implementation
Handles encrypted traffic routing with DNS leak prevention
"""
import socket
import struct
import threading
import logging
from typing import Optional
import time

logger = logging.getLogger(__name__)


class SOCKSProxyServer:
    """SOCKS5 proxy server with encryption and traffic analysis"""
    
    def __init__(self, host='127.0.0.1', port=9050, encryption_manager=None, 
                 dns_handler=None, traffic_analyzer=None):
        self.host = host
        self.port = port
        self.encryption_manager = encryption_manager
        self.dns_handler = dns_handler
        self.traffic_analyzer = traffic_analyzer
        self.running = False
        self.server_socket = None
        self.start_time = None
        self.connection_count = 0
        self.lock = threading.Lock()
    
    def run(self):
        """Start the proxy server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.start_time = time.time()
            
            logger.info(f"SOCKS5 Proxy running on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, addr):
        """Handle individual client connection"""
        try:
            with self.lock:
                self.connection_count += 1
            
            logger.info(f"Client connected from {addr}")
            
            # SOCKS5 handshake
            if not self.socks5_handshake(client_socket):
                return
            
            # Process requests
            self.process_request(client_socket)
            
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def socks5_handshake(self, client_socket):
        """Perform SOCKS5 authentication handshake"""
        try:
            # Receive greeting
            data = client_socket.recv(1024)
            if len(data) < 2:
                return False
            
            # Send response (no authentication required)
            response = struct.pack('!BB', 5, 0)
            client_socket.send(response)
            
            return True
        except Exception as e:
            logger.error(f"SOCKS5 handshake failed: {e}")
            return False
    
    def process_request(self, client_socket):
        """Process SOCKS5 request"""
        try:
            # Receive request
            data = client_socket.recv(1024)
            if len(data) < 4:
                return
            
            # Parse request
            cmd = data[1]
            
            if cmd == 1:  # CONNECT
                host, port = self.parse_connect_request(data)
                self.handle_connect(client_socket, host, port)
            elif cmd == 2:  # BIND
                self.send_error(client_socket, 7)  # Not supported
            elif cmd == 3:  # UDP ASSOCIATE
                self.send_error(client_socket, 7)  # Not supported
            
        except Exception as e:
            logger.error(f"Error processing request: {e}")
    
    def parse_connect_request(self, data):
        """Parse SOCKS5 CONNECT request"""
        addr_type = data[3]
        
        if addr_type == 1:  # IPv4
            host = '.'.join(str(b) for b in data[4:8])
            port = struct.unpack('!H', data[8:10])[0]
        elif addr_type == 3:  # Domain name
            domain_len = data[4]
            domain = data[5:5+domain_len].decode()
            host = domain
            port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
        elif addr_type == 4:  # IPv6
            host = ':'.join(f'{int.from_bytes(data[4+i:6+i], "big"):x}' 
                           for i in range(0, 16, 2))
            port = struct.unpack('!H', data[20:22])[0]
        else:
            host, port = '0.0.0.0', 0
        
        return host, port
    
    def handle_connect(self, client_socket, host, port):
        """Handle CONNECT request"""
        try:
            # Resolve DNS (use DNS handler if available)
            if self.dns_handler:
                resolved_ip = self.dns_handler.resolve(host)
            else:
                resolved_ip = socket.gethostbyname(host)
            
            logger.info(f"Connecting to {host}:{port} (resolved: {resolved_ip})")
            
            # Create server connection
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((resolved_ip, port))
            
            # Send success response
            response = struct.pack('!BBBBBBH', 5, 0, 0, 1, 
                                  *map(int, resolved_ip.split('.')), port)
            client_socket.send(response)
            
            # Start bidirectional relay
            self.relay_traffic(client_socket, server_socket, host, port)
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            self.send_error(client_socket, 1)  # General server failure
    
    def relay_traffic(self, client_socket, server_socket, host, port):
        """Relay traffic between client and server with encryption"""
        try:
            import select
            
            while self.running:
                readable, _, _ = select.select([client_socket, server_socket], [], [], 1)
                
                for sock in readable:
                    if sock == client_socket:
                        data = client_socket.recv(4096)
                        if not data:
                            return
                        
                        # Encrypt if manager available
                        if self.encryption_manager:
                            encrypted = self.encryption_manager.encrypt(data)
                            server_socket.send(encrypted)
                        else:
                            server_socket.send(data)
                        
                        # Track traffic
                        if self.traffic_analyzer:
                            self.traffic_analyzer.log_send(len(data), host, port)
                    
                    elif sock == server_socket:
                        data = server_socket.recv(4096)
                        if not data:
                            return
                        
                        # Decrypt if manager available
                        if self.encryption_manager:
                            decrypted = self.encryption_manager.decrypt(data)
                            client_socket.send(decrypted)
                        else:
                            client_socket.send(data)
                        
                        # Track traffic
                        if self.traffic_analyzer:
                            self.traffic_analyzer.log_receive(len(data), host, port)
        
        except Exception as e:
            logger.error(f"Error relaying traffic: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
    
    def send_error(self, client_socket, error_code):
        """Send SOCKS5 error response"""
        response = struct.pack('!BBBBBBH', 5, error_code, 0, 1, 0, 0, 0, 0)
        try:
            client_socket.send(response)
        except:
            pass
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("SOCKS5 Proxy stopped")
    
    def get_uptime(self):
        """Get proxy uptime in seconds"""
        if not self.start_time:
            return 0
        return time.time() - self.start_time
    
    def get_connection_count(self):
        """Get total connections handled"""
        with self.lock:
            return self.connection_count
