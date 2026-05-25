#!/usr/bin/env python3

import os
import sys
import time
import json
import csv
import curses
import threading
import socket
import struct
import ipaddress
import signal
import argparse
import pickle
import gzip
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any

try:
    from scapy.all import (
        sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, ARP, 
        DNS, DNSQR, DNSRR, Raw, get_if_list, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CONFIG = {
    'max_packets': 10000,
    'buffer_size': 1000,
    'auto_scroll': True,
    'save_raw': True,
    'max_payload_display': 500,
    'session_file': 'sniffer_session.pkl.gz'
}

class PacketData:
    def __init__(self, packet, timestamp=None):
        self.timestamp = timestamp or datetime.now()
        self.raw_packet = packet
        self.protocol = "UNKNOWN"
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.length = len(packet)
        self.payload = b""
        self.flags = ""
        self.info = ""
        self.anomalies = []
        self._parse_packet(packet)
    
    def _parse_packet(self, packet):
        if packet.haslayer(Ether):
            eth = packet[Ether]
            self.eth_src = eth.src
            self.eth_dst = eth.dst
            self.eth_type = eth.type
        
        if packet.haslayer(IP):
            ip = packet[IP]
            self.src_ip = ip.src
            self.dst_ip = ip.dst
            self.ttl = ip.ttl
            self.ip_flags = ip.flags
            self.fragment = ip.frag
            
            mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP"}
            self.protocol = mapping.get(ip.proto, f"IP-{ip.proto}")
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                self.src_port = tcp.sport
                self.dst_port = tcp.dport
                self.seq = tcp.seq
                self.ack = tcp.ack
                self.window = tcp.window
                self.flags = self._format_tcp_flags(tcp)
                
                if packet.haslayer(HTTPRequest):
                    self.protocol = "HTTP"
                    http = packet[HTTPRequest]
                    self.info = f"{http.Method.decode(errors='ignore')} {http.Path.decode(errors='ignore')}"
                    self.payload = bytes(http.payload) if http.payload else b""
                elif packet.haslayer(HTTPResponse):
                    self.protocol = "HTTP"
                    http = packet[HTTPResponse]
                    status = http.Status_Code.decode(errors='ignore') if hasattr(http, 'Status_Code') else "?"
                    self.info = f"HTTP/{http.Http_Version.decode(errors='ignore')} {status}"
                    self.payload = bytes(http.payload) if http.payload else b""
                elif packet.haslayer(Raw):
                    self.payload = packet[Raw].load
                
                self._detect_tcp_anomalies(tcp)
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                self.src_port = udp.sport
                self.dst_port = udp.dport
                
                if packet.haslayer(DNS):
                    self.protocol = "DNS"
                    self._parse_dns(packet[DNS])
                elif packet.haslayer(Raw):
                    self.payload = packet[Raw].load
            
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                self.info = f"Type={icmp.type} Code={icmp.code}"
                if packet.haslayer(Raw):
                    self.payload = packet[Raw].load
        
        elif packet.haslayer(ARP):
            self.protocol = "ARP"
            arp = packet[ARP]
            self.src_ip = arp.psrc
            self.dst_ip = arp.pdst
            self.info = f"{'Who has' if arp.op == 1 else 'Is at'} {arp.pdst}"
        else:
            self.info = f"Type: {hex(packet[Ether].type) if packet.haslayer(Ether) else 'Unknown'}"
    
    def _format_tcp_flags(self, tcp) -> str:
        flags = []
        if tcp.flags.S: flags.append("SYN")
        if tcp.flags.A: flags.append("ACK")
        if tcp.flags.F: flags.append("FIN")
        if tcp.flags.R: flags.append("RST")
        if tcp.flags.P: flags.append("PSH")
        if tcp.flags.U: flags.append("URG")
        return ",".join(flags) if flags else "-"
    
    def _parse_dns(self, dns):
        queries = []
        if dns.qdcount and dns.qdcount > 0:
            for i in range(dns.qdcount):
                qname = dns.qd[i].qname.decode(errors='ignore') if isinstance(dns.qd[i].qname, bytes) else str(dns.qd[i].qname)
                queries.append(f"Q: {qname} ({dns.qd[i].qtype})")
        
        answers = []
        if dns.ancount and dns.ancount > 0:
            for i in range(dns.ancount):
                rr = dns.an[i]
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors='ignore')
                answers.append(f"A: {rdata}")
        
        self.info = " | ".join(queries + answers) if queries or answers else f"Op: {dns.opcode}"
        try:
            self.payload = bytes(dns.payload) if dns.payload else b""
        except:
            self.payload = b""
    
    def _detect_tcp_anomalies(self, tcp):
        anomalies = []
        if tcp.flags.S and not tcp.flags.A:
            anomalies.append("Possible SYN scan")
        if tcp.flags == 0:
            anomalies.append("NULL flags (suspicious)")
        if tcp.flags.F and tcp.flags.P and tcp.flags.U:
            anomalies.append("XMAS scan pattern")
        if hasattr(self, 'fragment') and self.fragment > 0:
            anomalies.append("Fragmented packet")
        self.anomalies = anomalies
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'length': self.length,
            'flags': self.flags,
            'info': self.info,
            'anomalies': self.anomalies,
            'payload': self.payload.hex() if self.payload else ""
        }
    
    def __str__(self) -> str:
        time_str = self.timestamp.strftime("%H:%M:%S.%f")[:-3]
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
        alert = " [!]" if self.anomalies else ""
        return f"{time_str} | {self.protocol:6} | {src:21} -> {dst:21} | {self.length:4} | {self.info[:30]}{alert}"

class PacketFilter:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.protocol = None
        self.port = None
        self.port_direction = "either"
        self.show_anomalies_only = False
        self.search_term = None
    
    def matches(self, packet: PacketData) -> bool:
        if self.src_ip and packet.src_ip != self.src_ip:
            return False
        if self.dst_ip and packet.dst_ip != self.dst_ip:
            return False
        if self.protocol and packet.protocol.upper() != self.protocol.upper():
            return False
        if self.port:
            if self.port_direction == "src" and packet.src_port != self.port:
                return False
            elif self.port_direction == "dst" and packet.dst_port != self.port:
                return False
            elif self.port_direction == "either" and packet.src_port != self.port and packet.dst_port != self.port:
                return False
        if self.show_anomalies_only and not packet.anomalies:
            return False
        if self.search_term:
            s = self.search_term.lower()
            if (s not in packet.src_ip.lower() and 
                s not in packet.dst_ip.lower() and
                s not in packet.info.lower() and
                s not in packet.protocol.lower()):
                return False
        return True
    
    def is_active(self) -> bool:
        return any([self.src_ip, self.dst_ip, self.protocol, self.port, self.show_anomalies_only, self.search_term])
    
    def clear(self):
        self.__init__()
    
    def __str__(self) -> str:
        parts = []
        if self.src_ip: parts.append(f"src={self.src_ip}")
        if self.dst_ip: parts.append(f"dst={self.dst_ip}")
        if self.protocol: parts.append(f"proto={self.protocol}")
        if self.port: parts.append(f"port={self.port}({self.port_direction})")
        if self.show_anomalies_only: parts.append("anomalies-only")
        if self.search_term: parts.append(f"search='{self.search_term}'")
        return ", ".join(parts) if parts else "None"

class Statistics:
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.src_ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.start_time = datetime.now()
        self.packet_sizes = deque(maxlen=1000)
        self.timeline = deque(maxlen=100)
    
    def update(self, packet: PacketData):
        self.total_packets += 1
        self.total_bytes += packet.length
        self.protocol_counts[packet.protocol] += 1
        self.src_ip_counts[packet.src_ip] += 1
        self.dst_ip_counts[packet.dst_ip] += 1
        if packet.src_port:
            self.port_counts[f"{packet.src_port}/src"] += 1
        if packet.dst_port:
            self.port_counts[f"{packet.dst_port}/dst"] += 1
        self.packet_sizes.append(packet.length)
        
        now = datetime.now()
        if not self.timeline or (now - self.timeline[-1][0]).seconds >= 1:
            self.timeline.append((now, self.total_bytes))
    
    def get_bandwidth(self) -> float:
        if len(self.timeline) < 2:
            return 0.0
        time_diff = (self.timeline[-1][0] - self.timeline[0][0]).total_seconds()
        if time_diff == 0:
            return 0.0
        return ((self.timeline[-1][1] - self.timeline[0][1]) / 1024) / time_diff
    
    def get_report(self) -> Dict:
        duration = (datetime.now() - self.start_time).total_seconds()
        return {
            'duration_seconds': duration,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': self.total_packets / duration if duration > 0 else 0,
            'bytes_per_second': self.total_bytes / duration if duration > 0 else 0,
            'avg_packet_size': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0,
            'protocol_distribution': dict(self.protocol_counts),
            'top_source_ips': sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_dest_ips': sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_ports': sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }

class PacketSniffer:
    def __init__(self):
        self.packets = deque(maxlen=CONFIG['max_packets'])
        self.filtered_packets = []
        self.filter = PacketFilter()
        self.stats = Statistics()
        self.capture_thread = None
        self.running = False
        self.interface = None
        self.packet_count = 0
        self.lock = threading.Lock()
        self.selected_idx = 0
        self.scroll_offset = 0
        self.mode = "live"
        self.session_file = CONFIG['session_file']
        
    def packet_handler(self, packet):
        try:
            pkt_data = PacketData(packet)
            with self.lock:
                self.packets.append(pkt_data)
                self.stats.update(pkt_data)
                self.packet_count += 1
                if self.filter.matches(pkt_data):
                    self.filtered_packets.append(pkt_data)
        except Exception:
            pass
    
    def start_capture(self, interface=None, bpf_filter=None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed.")
        self.interface = interface
        self.running = True
        
        def capture():
            try:
                sniff(
                    iface=interface,
                    prn=self.packet_handler,
                    filter=bpf_filter,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except Exception:
                self.running = False
        
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()
        self.stats.reset()
    
    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def apply_filter(self):
        with self.lock:
            self.filtered_packets = [p for p in self.packets if self.filter.matches(p)]
            self.selected_idx = 0
            self.scroll_offset = 0
    
    def save_session(self, filename=None):
        filename = filename or self.session_file
        with gzip.open(filename, 'wb') as f:
            pickle.dump(list(self.packets), f)
        return filename
    
    def load_session(self, filename=None):
        filename = filename or self.session_file
        with gzip.open(filename, 'rb') as f:
            loaded = pickle.load(f)
            with self.lock:
                self.packets = deque(loaded, maxlen=CONFIG['max_packets'])
                self.apply_filter()
    
    def export_pcap(self, filename):
        packets = [p.raw_packet for p in self.packets if hasattr(p, 'raw_packet')]
        wrpcap(filename, packets)
        return filename
    
    def export_json(self, filename):
        data = [p.to_dict() for p in self.packets]
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return filename
    
    def export_csv(self, filename):
        if not self.packets:
            return filename
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.packets[0].to_dict().keys())
            writer.writeheader()
            for pkt in self.packets:
                writer.writerow(pkt.to_dict())
        return filename

class TextUI:
    def __init__(self, sniffer: PacketSniffer):
        self.sniffer = sniffer
        self.stdscr = None
        self.height = 0
        self.width = 0
        self.detail_mode = False
        self.detail_scroll = 0
        self.menu_active = False
        self.menu_items = [
            "Start Capture", "Stop Capture", "Clear Packets",
            "Set Filter", "View Statistics", "Export PCAP",
            "Export JSON", "Export CSV", "Save Session",
            "Load Session", "Help", "Quit"
        ]
        self.menu_idx = 0
        self.status_msg = ""
        self.status_time = 0
    
    def init_colors(self):
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    
    def draw_header(self):
        header = " Termux Packet Sniffer "
        status = " [RUNNING] " if self.sniffer.running else " [STOPPED] "
        filter_info = f" Filter: {self.sniffer.filter} "
        start_x = (self.width - len(header)) // 2
        
        self.stdscr.addstr(0, 0, "─" * self.width, curses.color_pair(4))
        self.stdscr.addstr(0, start_x, header, curses.color_pair(4) | curses.A_BOLD)
        self.stdscr.addstr(1, 0, status, curses.color_pair(2 if self.sniffer.running else 3))
        self.stdscr.addstr(1, len(status), filter_info[:self.width-len(status)-1], curses.color_pair(5))
        
        count_str = f" Packets: {self.sniffer.packet_count} "
        self.stdscr.addstr(1, self.width - len(count_str) - 1, count_str, curses.color_pair(1))
        self.stdscr.addstr(2, 0, "─" * self.width, curses.color_pair(4))
    
    def draw_packet_list(self):
        headers = "Time     | Proto  | Source                -> Destination           | Size | Info"
        self.stdscr.addstr(3, 0, headers[:self.width], curses.color_pair(4) | curses.A_BOLD)
        
        packets = self.sniffer.filtered_packets if self.sniffer.filter.is_active() else list(self.sniffer.packets)
        list_height = self.height - 5
        
        if self.sniffer.selected_idx >= self.sniffer.scroll_offset + list_height:
            self.sniffer.scroll_offset = self.sniffer.selected_idx - list_height + 1
        elif self.sniffer.selected_idx < self.sniffer.scroll_offset:
            self.sniffer.scroll_offset = self.sniffer.selected_idx

        for idx, i in enumerate(range(self.scroll_offset, min(len(packets), self.scroll_offset + list_height))):
            pkt = packets[i]
            style = curses.color_pair(1)
            if i == self.sniffer.selected_idx:
                style |= curses.A_REVERSE
            self.stdscr.addstr(4 + idx, 0, str(pkt)[:self.width].ljust(self.width), style)

    def main_loop(self, stdscr):
        self.stdscr = stdscr
        self.init_colors()
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        
        while True:
            self.height, self.width = self.stdscr.getmaxyx()
            self.stdscr.clear()
            self.draw_header()
            self.draw_packet_list()
            self.stdscr.refresh()
            
            try:
                ch = self.stdscr.getch()
                if ch == ord('q'):
                    break
                elif ch == curses.KEY_UP:
                    self.sniffer.selected_idx = max(0, self.sniffer.selected_idx - 1)
                elif ch == curses.KEY_DOWN:
                    packets_len = len(self.sniffer.filtered_packets if self.sniffer.filter.is_active() else self.sniffer.packets)
                    self.sniffer.selected_idx = min(max(0, packets_len - 1), self.sniffer.selected_idx + 1)
            except IOError:
                pass
            time.sleep(0.05)

if __name__ == "__main__":
    sniffer = PacketSniffer()
    if SCAPY_AVAILABLE:
        sniffer.start_capture()
    ui = TextUI(sniffer)
    curses.wrapper(ui.main_loop)
    sniffer.stop_capture()
