# Print version info without starting server
import sys
sys.path.insert(0, r"D:\AlistDrive\AlistDrive")
import auth_server
print(f"Module file: {auth_server.__file__}")
print(f"ADMIN_HTML contains 'REBUILT': {'REBUILT' in auth_server.ADMIN_HTML}")
print(f"ADMIN_HTML contains 'v1.14.0': {'v1.14.0' in auth_server.ADMIN_HTML}")
print(f"ADMIN_HTML contains 'v1.16.0': {'v1.16.0' in auth_server.ADMIN_HTML}")

# Find the version in ADMIN_HTML
import re
matches = re.findall(r'v?\d+\.\d+\.\d+[-\w]*', auth_server.ADMIN_HTML)
print(f"Version strings in ADMIN_HTML: {matches}")
