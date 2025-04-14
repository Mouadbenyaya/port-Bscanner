import socket
import concurrent.futures
import time
import ipaddress
import os
import sys
from datetime import datetime

def validate_ip(ip):
    """Validate if the input is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_hostname(hostname):
    """Validate if the input is a valid hostname and resolvable"""
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def scan_port(args):
    """Scan a single port and return port number and status"""
    host, port = args
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            return port, True
        else:
            return port, False
    except:
        s.close()
        return port, False

def print_progress(current, total, bar_length=50):
    """Display a progress bar in the console"""
    percent = float(current) * 100 / total
    arrow = '-' * int(percent/100 * bar_length - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\rProgress: [{arrow + spaces}] {percent:.2f}% ({current}/{total})")
    sys.stdout.flush()

def main():
    host = input("Enter the target host (default: 127.0.0.1): ") or "127.0.0.1"
    
    if not validate_ip(host) and not validate_hostname(host):
        print(f"Error: '{host}' is not a valid IP address or hostname.")
        return
    
    try:
        start_port = int(input("Enter starting port (default: 1): ") or "1")
        end_port = int(input("Enter ending port (default: 1024): ") or "1024")
        
        if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
            print("Port numbers must be between 1 and 65535.")
            return
        if start_port > end_port:
            print("Starting port must be less than or equal to ending port.")
            return
    except ValueError:
        print("Invalid port number. Using defaults.")
        start_port = 1
        end_port = 1024
    
    show_closed = input("Show closed ports? (y/n, default: n): ").lower() == 'y'
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{host}_{timestamp}.txt"
    
    ip_address = host
    if not validate_ip(host):
        try:
            ip_address = socket.gethostbyname(host)
            print(f"Hostname {host} resolved to {ip_address}")
        except socket.gaierror:
            print(f"Error resolving hostname {host}")
            return
    
    print(f"\nScanning {host} ({ip_address}) from port {start_port} to {end_port}...")
    print(f"Results will be saved to {filename}")
    
    start_time = time.time()
    total_ports = end_port - start_port + 1
    completed = 0
    open_ports = []
    
    scan_args = [(host, port) for port in range(start_port, end_port + 1)]
    
    with open(filename, 'w') as f:
        f.write(f"Scan results for {host} ({ip_address})\n")
        f.write(f"Scan range: {start_port}-{end_port}\n")
        f.write(f"Date and time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {
                executor.submit(scan_port, args): args[1]
                for args in scan_args
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open = future.result()
                completed += 1
                
                print_progress(completed, total_ports)
                
                if is_open:
                    open_ports.append(port)
                    status = "OPEN"
                    f.write(f"Port {port}: {status}\n")
                    print(f"\nPort {port} is open.")
                elif show_closed:
                    status = "CLOSED"
                  
                    f.write(f"Port {port}: {status}\n")
    
    
    duration = time.time() - start_time
    print(f"\n\nScan completed in {duration:.2f} seconds.")
    print(f"Found {len(open_ports)} open ports.")
    
    with open(filename, 'a') as f:
        f.write(f"\nScan completed in {duration:.2f} seconds.\n")
        f.write(f"Found {len(open_ports)} open ports.\n")
        if open_ports:
            f.write("\nSummary of open ports:\n")
            for port in sorted(open_ports):
                service = ""
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                f.write(f"Port {port}: {service}\n")
    
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")