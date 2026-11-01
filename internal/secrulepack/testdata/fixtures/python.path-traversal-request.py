import os

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    name = request.args.get("name")
    # ruleid: python.path-traversal-request
    with open(os.path.join(BASE, name)) as f:
        return f.read()


@app.route("/download")
def download():
    path = request.args["path"]
    # ruleid: python.path-traversal-request
    return send_file(path)


@app.route("/safe")
def safe():
    name = secure_filename(request.args.get("name"))
    # ok: python.path-traversal-request
    with open(os.path.join(BASE, name)) as f:
        return f.read()


def report():
    # ok: python.path-traversal-request
    with open(os.path.join(BASE, "report.txt")) as f:
        return f.read()
