from scapy.all import srp, Ether, ARP
import json
import psutil
import socket
import ipaddress
import threading
import os

def get_local_networks():
    networks = []
    interfaces = psutil.net_if_addrs()
    gateways = psutil.net_if_stats()
    for interface, addrs in interfaces.items():
        if interface in gateways and not gateways[interface].isup: continue
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                netmask = addr.netmask
                if netmask:
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        networks.append(str(network))
                    except Exception: continue
    return networks

def socket_check(ip, hosts):
    try:
        # Try to connect to a common port to see if host is alive
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        # Port 135/445 for Windows, 22 for Linux
        result = s.connect_ex((str(ip), 22))
        if result == 0: hosts.append({"ip": str(ip), "status": "alive (SSH)"})
        s.close()
    except Exception: pass

def run(**args):
    ip_ranges = args.get("ip_range")
    if not ip_ranges: ip_ranges = get_local_networks()
    elif isinstance(ip_ranges, str): ip_ranges = [ip_ranges]
    if not ip_ranges: return json.dumps({"error": "No networks found."})
    
    print(f"[*] In discovery module. User: {os.getlogin() if hasattr(os, 'getlogin') else 'unknown'}")
    all_hosts = []
    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False

    for ip_range in ip_ranges:
        if is_root:
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)
                for _, rcv in ans:
                    all_hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "type": "ARP"})
            except Exception: pass
        else:
            # Non-root fallback: Try scanning some IPs (limited to first 20 for speed)
            print("[!] Not root. Using socket fallback (limited).")
            net = ipaddress.IPv4Network(ip_range, strict=False)
            threads = []
            for ip in list(net.hosts())[:20]:
                t = threading.Thread(target=socket_check, args=(ip, all_hosts))
                t.start()
                threads.append(t)
            for t in threads: t.join()

    return json.dumps({"discovered_hosts": all_hosts, "count": len(all_hosts), "scanned": ip_ranges})
