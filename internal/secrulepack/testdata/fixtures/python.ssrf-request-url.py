import requests
import httpx
from urllib.request import urlopen
from flask import request

ALLOWED = {"https://api.example.com/status"}


def preview():
    url = request.args.get("url")
    # ruleid: python.ssrf-request-url
    r = requests.get(url, timeout=5)
    # ruleid: python.ssrf-request-url
    h = httpx.post(request.json["callback"], json={})
    # ruleid: python.ssrf-request-url
    u = urlopen(request.form["feed"])
    # ok: python.ssrf-request-url
    s = requests.get("https://api.example.com/status", params={"q": url})
    # ok: python.ssrf-request-url
    t = requests.post("https://api.example.com/hook", json={"url": url})
    return r.text + h.text + u.read().decode() + s.text + t.text


def lookup():
    # ok: python.ssrf-request-url
    r = requests.get("https://api.example.com/users/" + request.args["id"])
    return r.text


# The false-positive shape of the 1.1.0 rule: urllib's request module is
# not the web request.
def fetch_release(url):
    from urllib import request as urlrequest

    req = urlrequest.Request(url, headers={"Accept": "application/json"})
    # ok: python.ssrf-request-url
    with urlopen(req) as response:
        return response.read()
