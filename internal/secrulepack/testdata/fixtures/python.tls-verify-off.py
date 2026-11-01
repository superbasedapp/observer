import ssl
import requests
import httpx


def fetch(url, session, ca_bundle):
    # ruleid: python.tls-verify-off
    a = requests.get(url, verify=False)
    # ruleid: python.tls-verify-off
    client = httpx.Client(verify=False)
    # ruleid: python.tls-verify-off
    ctx = ssl._create_unverified_context()
    other = ssl.create_default_context()
    # ruleid: python.tls-verify-off
    other.verify_mode = ssl.CERT_NONE
    # ruleid: python.tls-verify-off
    session.verify = False
    # ok: python.tls-verify-off
    b = requests.get(url, verify=ca_bundle)
    # ok: python.tls-verify-off
    c = requests.get(url, verify=True)
    # ok: python.tls-verify-off
    other.verify_mode = ssl.CERT_REQUIRED
    return a, b, c, client, ctx


# The false-positive shapes of the 1.1.0 rule: an explicit opt-in flag
# and test code.
def build(no_verify_ssl):
    if no_verify_ssl:
        # ok: python.tls-verify-off
        return httpx.Client(verify=False)
    # ok: python.tls-verify-off
    return httpx.Client(verify=False) if no_verify_ssl else httpx.Client()


def test_self_signed_server(url):
    # ok: python.tls-verify-off
    assert requests.get(url, verify=False).ok


class TestClient:
    def test_insecure(self, url):
        # ok: python.tls-verify-off
        httpx.get(url, verify=False)


# Lane SEC-G4 audit finding 2: only a flag- or config-named condition is an
# opt-in; any other condition still matches.
def fetch_checked(url, cfg):
    resp = requests.get(url)
    if resp.status_code != 200:
        # ruleid: python.tls-verify-off
        resp = requests.get(url, verify=False)
    if cfg.skip_tls_verify:
        # ok: python.tls-verify-off
        resp = requests.get(url, verify=False)
    return resp


if __name__ == "__main__":
    # ruleid: python.tls-verify-off
    requests.get("https://example.invalid", verify=False)
