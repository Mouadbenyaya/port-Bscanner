"""
Helper functions for the port scanner
"""
import socket
import ipaddress
import re

def validate_ip(ip):
    """Validate if the input is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_hostname(hostname):
    """Validate if the input is a valid hostname"""
    # Basic hostname validation
    hostname_regex = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    return bool(hostname_regex.match(hostname))

def resolve_hostname(hostname):
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def reverse_dns_lookup(ip):
    """Perform reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def get_service_name(port, protocol='tcp'):
    """Get service name for a port"""
    try:
        return socket.getservbyport(port, protocol)
    except (socket.error, OSError):
        return "unknown"

def is_port_in_range(port):
    """Check if port is in valid range (1-65535)"""
    return 1 <= port <= 65535

def is_root():
    """Check if the script is running with root privileges"""
    import os
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def check_connectivity():
    """Test internet connectivity"""
    try:
        socket.create_connection(("www.google.com", 80), timeout=2)
        return True
    except:
        return False