"""
Configuration class for port scanner
"""

class Config:
    """Configuration settings for port scanner"""
    
    def __init__(self):
        # Target settings
        self.target = "127.0.0.1"
        self.start_port = 1
        self.end_port = 1024
        
        # Scan settings
        self.scan_type = "tcp"  # tcp, udp, stealth, full
        self.timeout = 1.0
        self.threads = 100
        self.show_closed = False
        self.randomize = False
        self.delay = 0
        
        # Feature settings 
        self.banner_grab = False
        self.vuln_check = False
        self.save_banners = False
        
        # Output settings
        self.output_format = "txt"  # txt, json, csv
        
    def to_dict(self):
        """Convert configuration to dictionary"""
        return {
            "target": self.target,
            "port_range": f"{self.start_port}-{self.end_port}",
            "scan_type": self.scan_type,
            "timeout": self.timeout,
            "threads": self.threads,
            "show_closed": self.show_closed,
            "randomize": self.randomize,
            "delay": self.delay,
            "banner_grab": self.banner_grab,
            "vuln_check": self.vuln_check,
            "output_format": self.output_format
        }