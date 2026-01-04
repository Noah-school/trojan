import platform
import os
import psutil
import json

def get_processor_name():
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        return line.split(":")[1].strip()
        except Exception: pass
    return platform.processor()

def run(**args):
    print("[*] In system_enum module.")
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "username": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
        "processor": get_processor_name(),
        "processes": [p.info for p in psutil.process_iter(['pid', 'name', 'username'])][:20]
    }
    return json.dumps(info)
