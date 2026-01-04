import platform
import os
import psutil
import json

def run(**args):
    print("[*] In system_enum module.")
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "username": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
        "processor": platform.processor(),
        "processes": [p.info for p in psutil.process_iter(['pid', 'name', 'username'])][:20]
    }
    return json.dumps(info)
