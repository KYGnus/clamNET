import os
from pathlib import Path

# Security settings (CHANGE THESE IN PRODUCTION!)
USERNAME = "admin"
PASSWORD = "admin"  # In production, use a strong password
SECRET_KEY = "clamNET"  # Should be a long, random string in production

# Path configurations
BASE_DIR = Path(os.getenv('APPDATA', os.path.expanduser('~')))
MAINDIR = str(BASE_DIR / "clamNET")  # Using proper path joining
UPLOADDIR = str(BASE_DIR / "clamNET" / "uploads")

# Installation files
LOCAL_INSTALL_FILE = "clamav-1.4.3.win.x64.msi"  # Should be in the same directory as your app
REMOTE_INSTALL_FILE = "C:\\Windows\\Temp\\clamav-installer.msi"
LOCAL_CVD_FILE = "daily.cvd"  # Default database file name

# Additional recommended settings
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
                     'exe', 'dll', 'js', 'vbs', 'ps1', 'zip', 'rar', '7z', 
                     'jpg', 'jpeg', 'png', 'pcap', 'pcapng'}