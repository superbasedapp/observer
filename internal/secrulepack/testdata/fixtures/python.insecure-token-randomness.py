import random
import secrets
import string


def make():
    # ruleid: python.insecure-token-randomness
    reset_token = "".join(random.choice(string.ascii_letters) for _ in range(32))
    # ruleid: python.insecure-token-randomness
    api_key = "%032x" % random.getrandbits(128)
    # ruleid: python.insecure-token-randomness
    otp = random.randint(100000, 999999)
    # ok: python.insecure-token-randomness
    password = secrets.token_urlsafe(16)
    # ok: python.insecure-token-randomness
    jitter = random.uniform(0.5, 1.5)
    # ok: python.insecure-token-randomness
    colour = random.choice(["red", "green"])
    return reset_token, api_key, otp, password, jitter, colour


# The false-positive shapes of the 1.1.0 rule: a value that is not a
# secret, and test code.
def context_token():
    # ok: python.insecure-token-randomness
    token = str(random.getrandbits(64))
    # ok: python.insecure-token-randomness
    session_id = random.getrandbits(128)
    return token, session_id


def test_secret_store():
    # ok: python.insecure-token-randomness
    secret = str(random.randint(0, 100))
    assert secret
