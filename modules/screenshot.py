import pyautogui
import base64
import os
from io import BytesIO

def run(**args):
    print("[*] In screenshot module. Capturing screen...")
    screenshot = pyautogui.screenshot()
    buffer = BytesIO()
    screenshot.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()
