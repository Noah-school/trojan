from scapy.all import sr1, sr, IP, TCP, ICMP
import json
import os

def run(**args):
    """
    Advanced SYN scan and OS detection using Scapy logic from Scrappy.
    Note: Requires root privileges.
    """
    target = args.get("target", "127.0.0.1")
    port_range_str = args.get("port_range", "1-1024")
    
    try:
        s_port, e_port = map(int, port_range_str.split('-'))
    except ValueError:
        return json.dumps({"error": "Invalid port range format. Use 'start-end'."})

    print(f"[*] In advanced port_scan module (Scrappy based). Scanning {target}...")
    
    open_ports = []
    
    # 1. SYN Scan
    for port in range(s_port, e_port + 1):
        # We use a short timeout for stealth and speed
        resp = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
        
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12: # SYN-ACK
                # Send RST to close the connection properly
                sr(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                open_ports.append(port)
                
    # 2. OS Fingerprinting (ICMP TTL based)
    os_guess = "Unknown"
    icmp_resp = sr1(IP(dst=target)/ICMP(), timeout=2, verbose=0)
    if icmp_resp:
        ttl = icmp_resp.ttl
        if ttl <= 64:
            os_guess = "Linux/Unix"
        elif ttl <= 128:
            os_guess = "Windows"
        else:
            os_guess = "Other (Solaris/AIX/etc)"
            
    return json.dumps({
        "target": target, 
        "open_ports": open_ports,
        "os_detection": {
            "guess": os_guess,
            "ttl": icmp_resp.ttl if icmp_resp else None
        },
        "method": "Scapy SYN Scan"
    })
