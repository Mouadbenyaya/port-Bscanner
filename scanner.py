
import socket
import concurrent.futures
import time
import random
import sys
import os
import struct
from datetime import datetime
import threading
from utils.helpers import validate_ip, validate_hostname, resolve_hostname, reverse_dns_lookup, get_service_name, is_root
from utils.banner import print_progress, print_result
from output.exporter import ResultExporter
from techniques.banner_grabber import BannerGrabber
from techniques.vulnerability_checker import VulnerabilityChecker

class PortScanner:
    """Main port scanner class"""
    
    def __init__(self, config):
        """Initialize scanner with configuration"""
        self.config = config
        self.ip_address = None
        self.hostname = None
        self.open_ports = []
        self.filtered_ports = []
        self.scan_results = {}
        self.banners = {}
        self.vulnerabilities = {}
        self.lock = threading.Lock()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialize components
        self.banner_grabber = BannerGrabber(self.config.timeout)
        self.vuln_checker = VulnerabilityChecker()
        self.exporter = ResultExporter(self.config.output_format, self.timestamp)
    
    def run(self):
        """Run the port scan"""
        if not self._prepare_target():
            return False
            
        print(f"\nScanning {self.config.target} ({self.ip_address})")
        print(f"Port range: {self.config.start_port}-{self.config.end_port}")
        print(f"Scan type: {self.config.scan_type}")
        
        start_time = time.time()
        
        # Prepare ports list
        ports = list(range(self.config.start_port, self.config.end_port + 1))
        if self.config.randomize:
            random.shuffle(ports)
        
        total_ports = len(ports)
        
        # Select scan method based on type
        if self.config.scan_type == 'tcp':
            self._scan_ports(ports, self._tcp_connect_scan)
        elif self.config.scan_type == 'udp':
            self._scan_ports(ports, self._udp_scan)
        elif self.config.scan_type == 'stealth':
            if not is_root():
                print("Stealth scan requires root privileges. Falling back to TCP Connect scan.")
                self._scan_ports(ports, self._tcp_connect_scan)
            else:
                self._scan_ports(ports, self._stealth_scan)
        elif self.config.scan_type == 'full':
            print("Performing TCP scan...")
            self._scan_ports(ports, self._tcp_connect_scan)
            print("\nPerforming UDP scan...")
            self._scan_ports(ports, self._udp_scan)
        
        # If banner grabbing is enabled, do it for open ports
        if self.config.banner_grab and self.open_ports:
            print("\nPerforming banner grabbing on open ports...")
            self._grab_banners()
        
        # If vulnerability checking is enabled
        if self.config.vuln_check and self.open_ports:
            print("\nPerforming basic vulnerability checks...")
            self._check_vulnerabilities()
        
        scan_duration = time.time() - start_time
        
        # Generate summary
        summary = {
            'target': self.config.target,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'scan_type': self.config.scan_type,
            'ports_scanned': total_ports,
            'open_ports': len(self.open_ports),
            'filtered_ports': len(self.filtered_ports),
            'scan_duration': scan_duration,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_results': self.scan_results
        }
        
        if self.config.banner_grab:
            summary['banners'] = self.banners
        
        if self.config.vuln_check:
            summary['vulnerabilities'] = self.vulnerabilities
        
        # Print summary
        self._print_summary(summary)
        
        # Export results
        filename = self.exporter.export(self.config.target, self.ip_address, summary)
        print(f"\nResultats sauvegardés dans: {filename}")
        
        return True
    
    def _prepare_target(self):
        """Prepare target for scanning (validation and resolution)"""
        # Validate target
        if validate_ip(self.config.target):
            self.ip_address = self.config.target
            # Try reverse DNS lookup
            self.hostname = reverse_dns_lookup(self.ip_address)
        elif validate_hostname(self.config.target):
            self.hostname = self.config.target
            # Resolve hostname to IP
            self.ip_address = resolve_hostname(self.config.target)
            if not self.ip_address:
                print(f"Erreur: Impossible de résoudre l'hostname {self.config.target}")
                return False
        else:
            print(f"Erreur: '{self.config.target}' n'est pas une adresse IP ou un hostname valide.")
            return False
        
        return True
    
    def _scan_ports(self, ports, scan_method):
        """Scan a list of ports using the specified scan method"""
        total_ports = len(ports)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_port = {
                executor.submit(scan_method, port): port for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_status, service = future.result()
                    
                    with self.lock:
                        completed += 1
                        print_progress(completed, total_ports, prefix="Scanning ports:")
                        
                        if port_status == "open":
                            self.open_ports.append(port)
                            self.scan_results[port] = {"status": port_status, "service": service}
                            print_result(port, port_status, service)
                        elif port_status == "filtered":
                            self.filtered_ports.append(port)
                            self.scan_results[port] = {"status": port_status, "service": service}
                            if self.config.show_closed:
                                print_result(port, port_status, service)
                        else:  # closed
                            if self.config.show_closed:
                                self.scan_results[port] = {"status": port_status, "service": service}
                                print_result(port, port_status, service)
                
                except Exception as e:
                    with self.lock:
                        completed += 1
                        print_progress(completed, total_ports, prefix="Scanning ports:")
                        print(f"\nError scanning port {port}: {e}")
    
    def _tcp_connect_scan(self, port):
        """Perform TCP connect scan on a single port"""
        if self.config.delay > 0:
            time.sleep(random.uniform(0, self.config.delay))
            
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.config.timeout)
        
        try:
            result = s.connect_ex((self.ip_address, port))
            s.close()
            
            if result == 0:
                service = get_service_name(port)
                return "open", service
            else:
                return "closed", None
        except Exception:
            s.close()
            return "closed", None
    
    def _udp_scan(self, port):
        """Perform UDP scan on a single port"""
        if self.config.delay > 0:
            time.sleep(random.uniform(0, self.config.delay))
            
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.config.timeout)
        
        # Send empty UDP packet
        try:
            s.sendto(b'', (self.ip_address, port))
            
            try:
                data, addr = s.recvfrom(1024)
                s.close()
                service = get_service_name(port, 'udp')
                return "open", service
            except socket.timeout:
                s.close()
                # This could be open or filtered
                return "filtered", get_service_name(port, 'udp')
        except Exception:
            s.close()
            return "closed", None
    
    def _stealth_scan(self, port):
        """Perform SYN stealth scan (requires raw socket access)"""
        if self.config.delay > 0:
            time.sleep(random.uniform(0, self.config.delay))
        
        
        try:
            
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.config.timeout)
            
      
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.config.timeout)
            result = s.connect_ex((self.ip_address, port))
            
            if result == 0:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                s.close()
                service = get_service_name(port)
                return "open", service
            else:
                s.close()
                return "closed", None
                
        except Exception as e:
            return "closed", None
    
    def _grab_banners(self):
        """Grab banners from open ports"""
        completed = 0
        total = len(self.open_ports)
        
        for port in self.open_ports:
            completed += 1
            print_progress(completed, total, prefix="Grabbing banners:")
            
            try:
                banner = self.banner_grabber.grab(self.ip_address, port)
                if banner:
                    self.banners[port] = banner
                    print(f"\nPort {port} banner: {banner[:100]}{'...' if len(banner) > 100 else ''}")
                    # Update scan results
                    self.scan_results[port]["banner"] = banner
            except Exception as e:
                print(f"\nError grabbing banner from port {port}: {e}")
    
    def _check_vulnerabilities(self):
        """Check for vulnerabilities on open ports"""
        completed = 0
        total = len(self.open_ports)
        
        for port in self.open_ports:
            completed += 1
            print_progress(completed, total, prefix="Checking vulnerabilities:")
            
            try:
               
                service = self.scan_results[port]["service"]
                banner = self.banners.get(port, "")
                
                # Check for vulnerabilities
                vulns = self.vuln_checker.check(port, service, banner)
                if vulns:
                    self.vulnerabilities[port] = vulns
                    print(f"\nPort {port} potential vulnerabilities: {', '.join(vulns)}")
                    # Update scan results
                    self.scan_results[port]["vulnerabilities"] = vulns
            except Exception as e:
                print(f"\nError checking vulnerabilities on port {port}: {e}")
    
    def _print_summary(self, summary):
        """Print scan summary"""
        print("\n" + "="*60)
        print(f"Scan Summary for {self.config.target} ({self.ip_address})")
        print("="*60)
        print(f"Scan type: {self.config.scan_type}")
        print(f"Ports scanned: {summary['ports_scanned']}")
        print(f"Open ports: {summary['open_ports']}")
        print(f"Filtered ports: {summary['filtered_ports']}")
        print(f"Scan duration: {summary['scan_duration']:.2f} seconds")
        print(f"Timestamp: {summary['timestamp']}")
        
        if self.open_ports:
            print("\nOpen ports:")
            for port in sorted(self.open_ports):
                port_info = self.scan_results[port]
                service = port_info["service"] if port_info["service"] else "unknown"
                print(f"  {port}/tcp: {service}")
                
                # If banner grabbing was enabled
                if self.config.banner_grab and port in self.banners:
                    banner = self.banners[port]
                    print(f"    Banner: {banner[:100]}{'...' if len(banner) > 100 else ''}")
                
                # If vulnerability checking was enabled
                if self.config.vuln_check and port in self.vulnerabilities:
                    vulns = self.vulnerabilities[port]
                    print(f"    Potential vulnerabilities: {', '.join(vulns)}")
        
        print("="*60)