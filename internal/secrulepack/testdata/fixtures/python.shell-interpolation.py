import os
import shlex
import subprocess
import sys

from flask import request


def lookup():
    host = request.args.get("host")
    # ruleid: python.shell-interpolation
    os.system("nslookup " + host)
    # ruleid: python.shell-interpolation
    subprocess.run(f"ping -c 1 {request.form['target']}", shell=True)
    # ok: python.shell-interpolation
    subprocess.run(["ping", "-c", "1", host])
    # ok: python.shell-interpolation
    os.system("nslookup " + shlex.quote(host))


def install(dest):
    # ok: python.shell-interpolation
    subprocess.check_call("pip install --target {} .".format(dest), shell=True)
    # ok: python.shell-interpolation
    os.system(f"{sys.executable} -m compileall {dest}")
