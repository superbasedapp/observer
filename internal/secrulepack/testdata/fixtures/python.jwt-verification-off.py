import jwt


def claims(token, key):
    # ruleid: python.jwt-verification-off
    a = jwt.decode(token, options={"verify_signature": False})
    # ruleid: python.jwt-verification-off
    b = jwt.decode(token, key, verify=False)
    # ruleid: python.jwt-verification-off
    c = jwt.decode(token, key, algorithms=["HS256", "none"])
    # ok: python.jwt-verification-off
    d = jwt.decode(token, key, algorithms=["HS256"])
    # ok: python.jwt-verification-off
    e = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
    return a, b, c, d, e
