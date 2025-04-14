"""
Raw socket implementation for advanced scanning techniques
"""
import socket
import struct
import random
import time
import os

class RawSocket:
    """Raw socket operations for advanced scanning"""
    
    def __init__(self, timeout=1.0):
        """Initialize raw socket handler"""
        self.timeout = timeout
        self.ip_id = random.randint(1000, 65535)
        
    def create_ip_header(self, src_ip, dst_ip, proto=socket.IPPROTO_TCP):
        """Create IP header"""
        # IP header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20  # IP header + TCP header
        ip_id = self.ip_id  # ID of this packet
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = proto
        ip_check = 0  # Checksum will be filled by kernel
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # Construct IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr
        )
        
        return ip_header
    
    def create_tcp_header(self, src_ip, dst_ip, src_port, dst_port, flags):
        """Create TCP header"""
        # TCP header fields
        tcp_seq = random.randint(1000, 1000000)
        tcp_ack_seq = 0
        tcp_doff = 5  # 4 bit field, size of tcp header in 32-bit words
        
        # TCP flags
        tcp_fin = 0
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        
        if 'F' in flags:
            tcp_fin = 1
        if 'S' in flags:
            tcp_syn = 1
        if 'R' in flags:
            tcp_rst = 1
        if 'P' in flags:
            tcp_psh = 1
        if 'A' in flags:
            tcp_ack = 1
        if 'U' in flags:
            tcp_urg = 1
        
        tcp_window = socket.htons(5840)  
        tcp_check = 0  # Checksum will be filled later
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        # Construct TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port,
            dst_port,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window,
            tcp_check,
            tcp_urg_ptr
        )
        
        # Pseudo header for checksum calculation
        source_address = socket.inet_aton(src_ip)
        dest_address = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH',
            source_address,
            dest_address,
            placeholder,
            protocol,
            tcp_length
        )
        
        psh = psh + tcp_header
        
        tcp_check = self.checksum(psh)
        
        # Repack the TCP header with the correct checksum
        tcp_header = struct.pack('!HHLLBBH',
            src_port,
            dst_port,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window
        ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
        
        return tcp_header
    
    def create_udp_header(self, src_port, dst_port, length=8):
        """Create UDP header"""
        udp_length = length
        udp_checksum = 0  # Can be zero in IPv4
        
        # Construct UDP header
        udp_header = struct.pack('!HHHH',
            src_port,
            dst_port,
            udp_length,
            udp_checksum
        )
        
        return udp_header
    
    def checksum(self, msg):
        """Calculate checksum for packet"""
        s = A = 0
        
        # Add up 16-bit words
        for i in range(0, len(msg), 2):
            if i + 1 < len(msg):
                a = msg[i]
                b = msg[i+1]
                s = s + (a + (b << 8))
            elif i + 1 == len(msg):
                s = s + msg[i]
        
        # Take only 16 bits out of the 32 bit sum
        s = s + (s >> 16)
        
        # One's complement
        s = ~s & 0xffff
        
        return s
    
    def send_raw_packet(self, dst_ip, dst_port, packet_type='syn'):
        """Send raw packet and receive response"""
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            src_ip = s.getsockname()[0]
            s.close()
            
            # Random source port
            src_port = random.randint(1025, 65535)
            
            # Create raw socket
            if packet_type in ['syn', 'tcp']:
                flags = 'S'  # SYN flag
                proto = socket.IPPROTO_TCP
            elif packet_type == 'fin':
                flags = 'F'  # FIN flag
                proto = socket.IPPROTO_TCP
            elif packet_type == 'ack':
                flags = 'A'  # ACK flag
                proto = socket.IPPROTO_TCP
            elif packet_type == 'udp':
                proto = socket.IPPROTO_UDP
            else:
                return None
            
            # Create socket based on protocol
            if proto == socket.IPPROTO_TCP:
                if os.name == 'nt':  # Windows
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                else:  # Linux/Unix
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Create IP header
                ip_header = self.create_ip_header(src_ip, dst_ip, proto)
                
                # Create TCP header
                tcp_header = self.create_tcp_header(src_ip, dst_ip, src_port, dst_port, flags)
                
                # Final packet
                packet = ip_header + tcp_header
                
            elif proto == socket.IPPROTO_UDP:
                if os.name == 'nt':  # Windows
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                else:  # Linux/Unix
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Create IP header
                ip_header = self.create_ip_header(src_ip, dst_ip, proto)
                
                # Create UDP header
                udp_header = self.create_udp_header(src_port, dst_port)
                
                # Final packet
                packet = ip_header + udp_header
            
            # Send packet
            s.settimeout(self.timeout)
            s.sendto(packet, (dst_ip, 0))
            
            # Receive response
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    response = s.recvfrom(1024)[0]
                    
                    # Parse response
                    ip_header = response[0:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    version_ihl = iph[0]
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    
                    if proto == socket.IPPROTO_TCP:
                        tcp_header = response[iph_length:iph_length+20]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4
                        flags = tcph[5]
                        
                        # Check if this is the response to our packet
                        if dest_port == src_port and source_port == dst_port:
                            # Check flags
                            if flags & 0x12 == 0x12:  # SYN+ACK flags
                                return "open"
                            elif flags & 0x14 == 0x14:  # RST+ACK flags
                                return "closed"
                    
                    elif proto == socket.IPPROTO_UDP:
                        # For UDP, if we receive an ICMP "port unreachable", the port is closed
                        if response[9] == 1:  # ICMP protocol
                            icmp_type = response[20]
                            if icmp_type == 3:  # Destination unreachable
                                return "closed"
                    
                except socket.timeout:
                    continue
            
            # If we got here, either we timed out or received something else
            # We'll assume the port is filtered
            return "filtered"
            
        except Exception as e:
            print(f"Error in raw socket operation: {e}")
            return None