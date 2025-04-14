"""
Banner grabbing implementation
"""
import socket
import ssl
import re
import time

class BannerGrabber:
    """Class for grabbing service banners from open ports"""
    
    def __init__(self, timeout=3.0):
        """Initialize with timeout"""
        self.timeout = timeout
        
        # Common probes to send to services
        self.probes = {
            21: b'USER anonymous\r\n',  # FTP
            22: b'SSH-2.0-OpenSSH_8.1\r\n',  # SSH
            23: b'\r\n',  # Telnet
            25: b'EHLO scanner.local\r\n',  # SMTP
            80: b'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 Scanner\r\nAccept: */*\r\n\r\n',  # HTTP
            110: b'USER test\r\n',  # POP3
            143: b'A001 CAPABILITY\r\n',  # IMAP
            443: b'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 Scanner\r\nAccept: */*\r\n\r\n',  # HTTPS
            3306: b'\x16\x03\x01\x00\x68MYSQL_NATIVE_PASSWORD',  # MySQL
            5432: b'\x00\x00\x00\x08\x04\xd2\x16\x2f',  # PostgreSQL
            6379: b'PING\r\n',  # Redis
            9200: b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',  # Elasticsearch
            27017: b'\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00\x74\x65\x73\x74\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01\x70\x69\x6e\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # MongoDB
        }
        
        # Default ports for certain services
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
    
    def grab(self, ip, port):
        """Grab banner from a specific port"""
        # Try different methods based on port
        if port == 443:
            return self._grab_https(ip, port)
        else:
            banner = self._grab_tcp(ip, port)
            if not banner:
                banner = self._grab_with_probe(ip, port)
            return banner
    
    def _grab_tcp(self, ip, port):
        """Grab banner using TCP connection"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            
            # Some services send banner immediately upon connection
            banner = s.recv(1024)
            s.close()
            
            if banner:
                return self._clean_banner(banner)
            return None
        except Exception:
            return None
    
    def _grab_https(self, ip, port):
        """Grab SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        return None
                    
                  
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                        cn = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                        issuer = cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                        return f"SSL Certificate: CN={cn}, Issuer={issuer}"
                    except ImportError:
                        return "SSL Certificate: Details unavailable (cryptography library missing)"
                    except Exception as e:
                        return f"SSL Certificate: Error extracting details - {str(e)}"
        except Exception:
            # Fall back to HTTP request
            return self._grab_with_probe(ip, port)
    
    def _grab_with_probe(self, ip, port):
        """Grab banner by sending a probe"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            
            # Send probe based on port
            if port in self.probes:
                s.send(self.probes[port])
            else:
                # Try generic HTTP probe for unknown ports
                s.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            
            time.sleep(0.5)  # Give some time for the response
            banner = s.recv(2048)
            s.close()
            
            if banner:
                return self._clean_banner(banner)
            return None
        except Exception:
            return None
    
    def _clean_banner(self, banner):
        """Clean and format the banner"""
        try:
            # Try to decode as UTF-8 first
            banner_str = banner.decode('utf-8', errors='replace')
            
            # Remove non-printable characters
            banner_str = re.sub(r'[\x00-\x1F\x7F]', '', banner_str)
            
            # Limit length and remove newlines
            banner_str = banner_str.replace('\r', ' ').replace('\n', ' ')
            
            return banner_str.strip()
        except Exception:
            # If decoding fails, return hex representation
            return banner.hex()[:100] + "..."