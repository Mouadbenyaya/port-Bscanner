"""
Export scan results to different formats without encryption
"""
import json
import csv
import os
from datetime import datetime

class ResultExporter:
    """Export scan results to various formats"""
    
    def __init__(self, format_type='txt', timestamp=None):
        """Initialize with output format"""
        self.format_type = format_type
        self.timestamp = timestamp if timestamp else datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = "scan_results"
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def export(self, target, ip_address, data):
        """Export data to the selected format"""
        if self.format_type == 'txt':
            return self._export_txt(target, ip_address, data)
        elif self.format_type == 'json':
            return self._export_json(target, ip_address, data)
        elif self.format_type == 'csv':
            return self._export_csv(target, ip_address, data)
        else:
            # Default to txt
            return self._export_txt(target, ip_address, data)
    
    def _get_filename(self, target, extension):
        """Generate filename with target and timestamp"""
        safe_target = target.replace(':', '_').replace('/', '_')
        filename = f"scan_{safe_target}_{self.timestamp}"
        return os.path.join(self.output_dir, f"{filename}.{extension}")
    
    def _export_txt(self, target, ip_address, data):
        """Export results to text format"""
        filename = self._get_filename(target, 'txt')
        
        content = ""
        content += "="*60 + "\n"
        content += f"SCAN REPORT: {target} ({ip_address})\n"
        content += "="*60 + "\n"
        content += f"Date: {data['timestamp']}\n"
        content += f"Scan type: {data['scan_type']}\n"
        content += f"Ports scanned: {data['ports_scanned']}\n"
        content += f"Duration: {data['scan_duration']:.2f} seconds\n\n"
        
        content += "-"*60 + "\n"
        content += "SCAN RESULTS\n"
        content += "-"*60 + "\n"
        
        # Print open ports
        if data['open_ports'] > 0:
            content += "OPEN PORTS:\n"
            for port, info in sorted(data['scan_results'].items()):
                if info['status'] == 'open':
                    content += f"Port {port}: {info['status'].upper()} - Service: {info['service']}\n"
                    
                    # If banner exists
                    if 'banner' in info:
                        content += f"  Banner: {info['banner'][:100]}{'...' if len(info['banner']) > 100 else ''}\n"
                    
                    # If vulnerabilities exist
                    if 'vulnerabilities' in info:
                        content += "  Potential vulnerabilities:\n"
                        for vuln in info['vulnerabilities']:
                            content += f"    - {vuln}\n"
            content += "\n"
        else:
            content += "No open ports found.\n\n"
        
        # Print filtered ports if any
        if data['filtered_ports'] > 0:
            content += "FILTERED PORTS:\n"
            filtered_count = 0
            for port, info in sorted(data['scan_results'].items()):
                if info['status'] == 'filtered' or info['status'] == 'open|filtered':
                    content += f"Port {port}: {info['status'].upper()}\n"
                    filtered_count += 1
                    if filtered_count >= 20:  # Limit to avoid huge reports
                        content += f"... and {data['filtered_ports'] - 20} more filtered ports\n"
                        break
            content += "\n"
        
        content += "="*60 + "\n"
        content += "END OF REPORT\n"
        content += "="*60 + "\n"
        
        with open(filename, 'w') as f:
            f.write(content)
        
        return filename
    
    def _export_json(self, target, ip_address, data):
        """Export results to JSON format"""
        filename = self._get_filename(target, 'json')
        
        # Convert to JSON string
        json_data = json.dumps(data, indent=2)
        
        with open(filename, 'w') as f:
            f.write(json_data)
        
        return filename
    
    def _export_csv(self, target, ip_address, data):
        """Export results to CSV format"""
        filename = self._get_filename(target, 'csv')
        
        # Standard CSV export
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status', 'Service', 'Banner', 'Vulnerabilities'])
            
            for port, info in sorted(data['scan_results'].items()):
                banner = info.get('banner', '')
                vulns = ', '.join(info.get('vulnerabilities', []))
                writer.writerow([port, info['status'], info['service'], banner, vulns])
        
        return filename