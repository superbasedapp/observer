import os
import shlex
import subprocess

from flask import request


def run_listing(directory):
    # ruleid: python.shell-interpolation
    os.system("ls -l " + directory)


def listing():
    run_listing(request.args.get("dir"))


def archive_name():
    return request.form["archive"]


def archive():
    # ruleid: python.shell-interpolation
    subprocess.run("tar tf " + archive_name(), shell=True)


# The sanitizer sits in the helper: the value is shell-quoted before the
# caller interpolates it.
def quoted(value):
    return shlex.quote(value)


def listing_quoted():
    # ok: python.shell-interpolation
    os.system("ls -l " + quoted(request.args.get("dir")))

