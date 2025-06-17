#!/usr/bin/env python3

print("dos detector by Giovanni")

import time
import logging
import os
import platform
from collections import defaultdict, deque
import traceback

scapy_core_imported = False
scapy_arch_windows_imported = False
scapy_utils_imported = False

print("Attempting to import Scapy components...")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    print(f"SUCCESS: Imported core components (sniff, IP, etc., conf) from scapy.all")
    scapy_core_imported = True
except ImportError as e:
    print(f"ERROR: Failed to import core components from scapy.all: {e}")
except Exception as e:
    print(f"ERROR: An unexpected error occurred importing from scapy.all: {e}")

if platform.system() == "Windows":
    try:
        from scapy.arch.windows import get_windows_if_list
        print("SUCCESS: Imported get_windows_if_list from scapy.arch.windows")
        scapy_arch_windows_imported = True
    except ImportError as e:
        print(f"ERROR: Failed to import get_windows_if_list from scapy.arch.windows: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred importing from scapy.arch.windows: {e}")
else:
    try:
        from scapy.utils import get_if_list
        print("SUCCESS: Imported get_if_list from scapy.utils")
        scapy_utils_imported = True
    except ImportError as e:
        print(f"ERROR: Failed to import get_if_list from scapy.utils: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred importing from scapy.utils: {e}")

if not scapy_core_imported:
    print("CRITICAL ERROR: Essential Scapy core components could not be imported. The script cannot continue.")
    exit()
else:
    print("Scapy core components seem to be imported successfully.")
    conf.verb = 0

print("\nAttempting to import Colorama...")
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    print("SUCCESS: Colorama imported and initialized successfully.")
except ImportError:
    print("WARNING: Colorama is not installed. Colors will not be available. Install with 'pip install colorama'")
    class EmptyColorama:
        def __getattr__(self, name): return ""
    Fore = EmptyColorama()
    Style = EmptyColorama()
except Exception as e:
    print(f"ERROR: An unexpected error occurred importing or initializing Colorama: {e}")
    class EmptyColorama:
        def __getattr__(self, name): return ""
    Fore = EmptyColorama()
    Style = EmptyColorama()

print("-" * 30)

TIME_WINDOW = 10
GENERAL_PACKET_THRESHOLD = 250
SYN_PACKET_THRESHOLD = 100
UDP_PACKET_THRESHOLD = 150
ICMP_ECHO_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
TCP_NULL_SCAN_THRESHOLD = 5
TCP_FIN_SCAN_THRESHOLD = 5
TCP_XMAS_SCAN_THRESHOLD = 5
LOG_FILE = "dos_detector.log"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s" # <<< --- MODIFIED: Added %(asctime)s back --- >>>

logger = logging.getLogger("dos detector")
logger.setLevel(LOG_LEVEL)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR if LOG_LEVEL > logging.DEBUG else logging.DEBUG)
logging.getLogger("scapy.loading").setLevel(logging.ERROR if LOG_LEVEL > logging.DEBUG else logging.DEBUG)

class ColoredFormatter(logging.Formatter):
    LOG_COLORS = {logging.DEBUG: Fore.CYAN, logging.INFO: Fore.GREEN, logging.WARNING: Fore.YELLOW, logging.ERROR: Fore.RED, logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,}
    def format(self, record):
        log_message = super().format(record)
        if 'colorama' in globals() and isinstance(globals()['colorama'], type(os)): return f"{self.LOG_COLORS.get(record.levelno, Fore.WHITE)}{log_message}{Style.RESET_ALL}"
        return log_message
ch = logging.StreamHandler()
ch.setFormatter(ColoredFormatter(LOG_FORMAT))
logger.addHandler(ch)
if LOG_FILE:
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f: f.write(f"# dos detector Log File - Initialized at {time.asctime()}\n")
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(fh)
    except IOError as e:
        logger.error(f"{Fore.RED}Could not open or write to log file {LOG_FILE}: {e}. Logging to file will be disabled.{Style.RESET_ALL}")
        LOG_FILE = None

ip_activity_monitor = defaultdict(lambda: {
    'total_packets': deque(), 'syn_packets': deque(), 'udp_packets': deque(),
    'icmp_echo_packets': deque(), 'tcp_null_scan_packets': deque(),
    'tcp_fin_scan_packets': deque(), 'tcp_xmas_scan_packets': deque(),
    'scanned_ports_tcp': defaultdict(lambda: deque()),
    'scanned_ports_udp': defaultdict(lambda: deque()),
    'last_alert_time': defaultdict(float), 'alert_details': defaultdict(set)
})
ALERT_COOLDOWN = 30

def log_alert(ip, alert_type, details_msg, specific_detail=None):
    current_time = time.time()
    cooldown_key = (ip, alert_type)
    if current_time - ip_activity_monitor[ip]['last_alert_time'][cooldown_key] > ALERT_COOLDOWN:
        logger.warning(f"[ALERT - {alert_type}] Source IP: {ip} - {details_msg}")
        ip_activity_monitor[ip]['last_alert_time'][cooldown_key] = current_time
        if specific_detail is not None:
            ip_activity_monitor[ip]['alert_details'][alert_type].clear()

def prune_deque(dq, current_time, window):
    while dq and dq[0] < current_time - window: dq.popleft()

def get_recent_details_str(ip, alert_type, max_items=3):
    details_set = ip_activity_monitor[ip]['alert_details'][alert_type]
    if not details_set: return ""
    items_to_show = list(details_set)[:max_items]
    details_str = ", ".join(map(str, items_to_show))
    if len(details_set) > max_items: details_str += f", and {len(details_set) - max_items} more"
    return f" (e.g., ports: {details_str})"

def process_packet(packet):
    try:
        if not IP in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()
        ip_stats = ip_activity_monitor[src_ip]

        for key in ['total_packets', 'syn_packets', 'udp_packets', 'icmp_echo_packets', 'tcp_null_scan_packets', 'tcp_fin_scan_packets', 'tcp_xmas_scan_packets']:
            prune_deque(ip_stats[key], current_time, TIME_WINDOW)
        for port_dq_map in [ip_stats['scanned_ports_tcp'], ip_stats['scanned_ports_udp']]:
            for port in list(port_dq_map.keys()):
                prune_deque(port_dq_map[port], current_time, TIME_WINDOW * 2)
                if not port_dq_map[port]: del port_dq_map[port]
        
        ip_stats['total_packets'].append(current_time)

        if len(ip_stats['total_packets']) > GENERAL_PACKET_THRESHOLD:
            log_alert(src_ip, "High Volume", f"Total Packets: {len(ip_stats['total_packets'])} in last {TIME_WINDOW}s.")

        if TCP in packet:
            tcp_layer = packet[TCP]
            dst_port_tcp = tcp_layer.dport
            ip_stats['scanned_ports_tcp'][dst_port_tcp].append(current_time)
            ip_stats['alert_details']["TCP Port Scan"].add(dst_port_tcp)
            flags = tcp_layer.flags
            if flags == 'S' or flags == 2:
                ip_stats['syn_packets'].append(current_time)
                ip_stats['alert_details']["TCP SYN Flood"].add(dst_port_tcp)
                if len(ip_stats['syn_packets']) > SYN_PACKET_THRESHOLD:
                    details = get_recent_details_str(src_ip, "TCP SYN Flood")
                    log_alert(src_ip, "TCP SYN Flood", f"SYN Packets: {len(ip_stats['syn_packets'])} in last {TIME_WINDOW}s{details}.")
            elif flags == 0:
                ip_stats['tcp_null_scan_packets'].append(current_time)
                ip_stats['alert_details']["TCP NULL Scan"].add(dst_port_tcp)
                if len(ip_stats['tcp_null_scan_packets']) > TCP_NULL_SCAN_THRESHOLD:
                    details = get_recent_details_str(src_ip, "TCP NULL Scan")
                    log_alert(src_ip, "TCP NULL Scan", f"NULL Scan Packets: {len(ip_stats['tcp_null_scan_packets'])} in last {TIME_WINDOW}s{details}.")
            elif flags == 'F' or flags == 1:
                ip_stats['tcp_fin_scan_packets'].append(current_time)
                ip_stats['alert_details']["TCP FIN Scan"].add(dst_port_tcp)
                if len(ip_stats['tcp_fin_scan_packets']) > TCP_FIN_SCAN_THRESHOLD:
                    details = get_recent_details_str(src_ip, "TCP FIN Scan")
                    log_alert(src_ip, "TCP FIN Scan", f"FIN Scan Packets: {len(ip_stats['tcp_fin_scan_packets'])} in last {TIME_WINDOW}s{details}.")
            elif flags == 'FPU' or flags == 0x29:
                ip_stats['tcp_xmas_scan_packets'].append(current_time)
                ip_stats['alert_details']["TCP XMAS Scan"].add(dst_port_tcp)
                if len(ip_stats['tcp_xmas_scan_packets']) > TCP_XMAS_SCAN_THRESHOLD:
                    details = get_recent_details_str(src_ip, "TCP XMAS Scan")
                    log_alert(src_ip, "TCP XMAS Scan", f"XMAS (FPU) Packets: {len(ip_stats['tcp_xmas_scan_packets'])} in last {TIME_WINDOW}s{details}.")
        elif UDP in packet:
            udp_layer = packet[UDP]
            dst_port_udp = udp_layer.dport
            ip_stats['scanned_ports_udp'][dst_port_udp].append(current_time)
            ip_stats['alert_details']["UDP Port Scan"].add(dst_port_udp)
            ip_stats['udp_packets'].append(current_time)
            if len(ip_stats['udp_packets']) > UDP_PACKET_THRESHOLD:
                details = get_recent_details_str(src_ip, "UDP Flood")
                log_alert(src_ip, "UDP Flood", f"UDP Packets: {len(ip_stats['udp_packets'])} in last {TIME_WINDOW}s{details}.")
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            if icmp_layer.type == 8:
                ip_stats['icmp_echo_packets'].append(current_time)
                if len(ip_stats['icmp_echo_packets']) > ICMP_ECHO_THRESHOLD:
                    log_alert(src_ip, "ICMP Echo Flood", f"ICMP Echo Requests: {len(ip_stats['icmp_echo_packets'])} in last {TIME_WINDOW}s.")
        if len(ip_stats['scanned_ports_tcp']) > PORT_SCAN_THRESHOLD:
            details = get_recent_details_str(src_ip, "TCP Port Scan")
            log_alert(src_ip, "TCP Port Scan", f"Scanned {len(ip_stats['scanned_ports_tcp'])} unique TCP ports in last {TIME_WINDOW*2}s{details}.", specific_detail="ports")
        if len(ip_stats['scanned_ports_udp']) > PORT_SCAN_THRESHOLD:
            details = get_recent_details_str(src_ip, "UDP Port Scan")
            log_alert(src_ip, "UDP Port Scan", f"Scanned {len(ip_stats['scanned_ports_udp'])} unique UDP ports in last {TIME_WINDOW*2}s{details}.", specific_detail="ports")
    except Exception as e_proc:
        logger.error(f"{Fore.RED}[FATAL in process_packet] Unhandled exception for packet from {packet.src if IP in packet else 'Unknown Source'}: {e_proc}{Style.RESET_ALL}")
        logger.error(f"{Fore.RED}Traceback: {traceback.format_exc()}{Style.RESET_ALL}")

def start_sniffing(interface_to_sniff_on=None):
    actual_interface_to_use = interface_to_sniff_on
    interface_name_for_log = "N/A"
    if interface_to_sniff_on is None:
        scapy_default_iface = conf.iface
        if scapy_default_iface:
            actual_interface_to_use = scapy_default_iface
            if hasattr(scapy_default_iface, 'name') and scapy_default_iface.name: interface_name_for_log = scapy_default_iface.name
            elif hasattr(scapy_default_iface, 'description') and scapy_default_iface.description: interface_name_for_log = scapy_default_iface.description
            else: interface_name_for_log = str(scapy_default_iface)
            logger.info(f"[*] No specific interface provided. Using Scapy's default: '{Style.BRIGHT}{Fore.CYAN}{interface_name_for_log}{Style.RESET_ALL}'")
        else:
            logger.error(f"{Fore.RED}[FATAL] No interface specified and Scapy has no default interface configured. Please specify an interface.{Style.RESET_ALL}"); return
    else:
        interface_name_for_log = interface_to_sniff_on
        logger.info(f"[*] Starting packet sniffing on specified interface: '{Style.BRIGHT}{Fore.CYAN}{interface_name_for_log}{Style.RESET_ALL}'...")
    logger.info(f"Monitoring thresholds per IP in {TIME_WINDOW}s window (Alert Cooldown: {ALERT_COOLDOWN}s):")
    logger.info(f"  General Packets: >{GENERAL_PACKET_THRESHOLD}"); logger.info(f"  TCP SYN Packets: >{SYN_PACKET_THRESHOLD}"); logger.info(f"  UDP Packets:     >{UDP_PACKET_THRESHOLD}"); logger.info(f"  ICMP Echo Pkts:  >{ICMP_ECHO_THRESHOLD}"); logger.info(f"  Port Scan (TCP/UDP): >{PORT_SCAN_THRESHOLD} unique ports in {TIME_WINDOW*2}s"); logger.info(f"  TCP NULL/FIN/XMAS Scans: >{TCP_NULL_SCAN_THRESHOLD} packets respectively in {TIME_WINDOW}s")
    if LOG_FILE: logger.info(f"Alerts will be logged to console and '{LOG_FILE}'")
    else: logger.info("Alerts will be logged to console only (file logging disabled).")
    logger.info(f"{Fore.GREEN}dos detector is now active... Press Ctrl+C to stop.{Style.RESET_ALL}")
    try:
        sniff(iface=actual_interface_to_use, prn=process_packet, store=0, stop_filter=lambda x: False)
    except PermissionError: logger.critical(f"{Fore.RED}[FATAL] PermissionError: You need to run this script with root or administrator privileges.{Style.RESET_ALL}")
    except OSError as e:
        if "No such device" in str(e) or "Network adapter not found" in str(e) or ("Cannot open L2 socket" in str(e) and actual_interface_to_use is not None) or ("The system cannot find the device specified" in str(e)):
             logger.critical(f"{Fore.RED}[FATAL] OSError: Network interface '{interface_name_for_log}' not found, invalid, or could not be opened.{Style.RESET_ALL}")
        else: logger.critical(f"{Fore.RED}[FATAL] OSError: {e}. Npcap/libpcap might not be installed or configured correctly.{Style.RESET_ALL}")
    except Exception as e: logger.critical(f"{Fore.RED}[FATAL] An unexpected error occurred during sniffing: {e}{Style.RESET_ALL}")
    finally:
        logger.info(f"{Fore.BLUE}dos detector sniffing stopped.{Style.RESET_ALL}")
        if 'colorama' in globals() and isinstance(globals()['colorama'], type(os)): colorama.deinit()

if __name__ == "__main__":
    network_interface_to_use = None
    start_sniffing(interface_to_sniff_on=network_interface_to_use)