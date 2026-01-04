import pyautogui
import base64
import os
from io import BytesIO

def run(**args):
    """Captures a screenshot of the primary monitor."""
    print("[*] In screenshot module. Capturing screen...")
    
    # 1. Take screenshot
    screenshot = pyautogui.screenshot()
    
    # 2. Save to memory buffer
    buffer = BytesIO()
    screenshot.save(buffer, format="PNG")
    
    # 3. Base64 encode the binary data
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return img_str
