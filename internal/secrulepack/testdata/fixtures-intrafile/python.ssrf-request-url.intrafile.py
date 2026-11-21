import urllib.parse

import requests
from flask import request


def fetch(url):
    # ruleid: python.ssrf-request-url
    return requests.get(url, timeout=5)


def preview():
    return fetch(request.args.get("url")).text


def requested_url():
    return request.args["url"]


def preview_returned():
    # ruleid: python.ssrf-request-url
    return requests.get(requested_url(), timeout=5).text


# The sanitizer sits in the helper: the value is URL-quoted before the
# caller fetches it.
def quoted(value):
    return urllib.parse.quote(value)


def preview_quoted():
    # ok: python.ssrf-request-url
    return requests.get(quoted(request.args.get("url")), timeout=5).text
