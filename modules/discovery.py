from scapy.all import srp, Ether, ARP
import json
import psutil
import socket
import ipaddress
import threading
import os

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 8080]

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

def advanced_socket_check(ip, hosts, semaphore):
    with semaphore:
        found_ports = []
        hostname = "Unknown"
        is_alive = False
        
        for port in COMMON_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1) # Faster timeout
                if s.connect_ex((str(ip), port)) == 0:
                    found_ports.append(port)
                    is_alive = True
                    break # Success, host is alive. Don't probe more ports to save time.
                s.close()
            except Exception: pass
            
        if is_alive:
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except Exception: pass
            
            hosts.append({
                "ip": str(ip),
                "hostname": hostname,
                "open_ports": found_ports,
                "type": "TCP Probe"
            })

def run(**args):
    ip_ranges = args.get("ip_range")
    if not ip_ranges: ip_ranges = get_local_networks()
    elif isinstance(ip_ranges, str): ip_ranges = [ip_ranges]
    
    print(f"[*] In discovery module. User: {os.getlogin() if hasattr(os, 'getlogin') else 'unknown'}")
    all_hosts = []
    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False

    for ip_range in ip_ranges:
        if is_root:
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)
                for _, rcv in ans:
                    name = "Unknown"
                    try: name = socket.gethostbyaddr(rcv.psrc)[0]
                    except Exception: pass
                    all_hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "hostname": name, "type": "ARP"})
            except Exception: pass
        else:
            net = ipaddress.IPv4Network(ip_range, strict=False)
            hosts_to_scan = list(net.hosts())
            
            # Smart limit for no-root: only scan first 256 hosts if network is large
            if net.prefixlen < 24:
                print(f"[!] Network {ip_range} is too large for no-root scan. Limiting to first 256 hosts.")
                hosts_to_scan = hosts_to_scan[:256]
                
            print(f"[*] Not root. Performing multi-port TCP scan on {len(hosts_to_scan)} potential hosts...")
            
            semaphore = threading.Semaphore(100) # Faster concurrency
            threads = []
            for ip in hosts_to_scan:
                t = threading.Thread(target=advanced_socket_check, args=(ip, all_hosts, semaphore))
                t.start()
                threads.append(t)
            
            for t in threads: t.join()

    return json.dumps({"discovered_hosts": all_hosts, "count": len(all_hosts), "scanned": ip_ranges})
