import os

from flask import request, send_file
from werkzeug.utils import secure_filename


def serve(name):
    # ruleid: python.path-traversal-request
    return send_file(name)


def download():
    return serve(request.args.get("name"))


def requested_path():
    return request.args["path"]


def read_requested():
    # ruleid: python.path-traversal-request
    with open(requested_path()) as handle:
        return handle.read()


# The sanitizer sits in the helper: the name is reduced to a base name
# before the caller opens it.
def clean_name(name):
    return secure_filename(os.path.basename(name))


def read_clean():
    # ok: python.path-traversal-request
    with open(clean_name(request.args["name"])) as handle:
        return handle.read()
