from urllib.parse import quote

from flask import redirect, request


# Cross-function taint in one file (--taint-intrafile): the value from the
# web request is handed to a helper that redirects to it.
def send_to(target):
    # ruleid: python.open-redirect
    return redirect(target)


def done():
    return send_to(request.args.get("next"))


def return_target():
    return request.form["return_to"]


def finish():
    # ruleid: python.open-redirect
    return redirect(return_target())


# The sanitizer sits in the helper: the value is quoted before the caller
# redirects to it.
def quoted(value):
    return quote(value)


def bounce():
    # ok: python.open-redirect
    return redirect(quoted(request.args.get("next")))
