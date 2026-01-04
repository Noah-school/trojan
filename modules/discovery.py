from scapy.all import srp, Ether, ARP
import json
import psutil
import socket
import ipaddress

def get_local_networks():
    """Detects active local network ranges (CIDR)."""
    networks = []
    interfaces = psutil.net_if_addrs()
    gateways = psutil.net_if_stats()

    for interface, addrs in interfaces.items():
        # Skip down interfaces
        if interface in gateways and not gateways[interface].isup:
            continue
            
        for addr in addrs:
            # Look for IPv4 addresses that aren't loopback
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                netmask = addr.netmask
                if netmask:
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        networks.append(str(network))
                    except Exception:
                        continue
    return networks

def run(**args):
    """
    Performs an ARP sweep to discover active hosts.
    If ip_range is not provided, it automatically detects local subnets.
    """
    ip_ranges = args.get("ip_range")
    if not ip_ranges:
        print("[*] No IP range provided. Detecting local networks...")
        ip_ranges = get_local_networks()
    elif isinstance(ip_ranges, str):
        ip_ranges = [ip_ranges]

    if not ip_ranges:
        return json.dumps({"error": "No active network interfaces found."})

    print(f"[*] In autonomous discovery module. Targets: {', '.join(ip_ranges)}")
    
    all_hosts = []
    
    for ip_range in ip_ranges:
        try:
            # Send ARP requests
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)
            
            for _, rcv in ans:
                all_hosts.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc,
                    "network": ip_range
                })
        except Exception as e:
            print(f"[-] Error sweeping {ip_range}: {e}")
            continue
        
    return json.dumps({
        "discovered_hosts": all_hosts,
        "count": len(all_hosts),
        "scanned_networks": ip_ranges
    })
