import hashlib


def store(user, password, content):
    # ruleid: python.weak-password-hash
    user.digest = hashlib.md5(password.encode()).hexdigest()
    # ruleid: python.weak-password-hash
    user.digest = hashlib.sha1(password).hexdigest()
    # ruleid: python.weak-password-hash
    user.digest = hashlib.sha256(user.password.encode("utf-8")).hexdigest()
    # ok: python.weak-password-hash
    etag = hashlib.md5(content).hexdigest()
    # ok: python.weak-password-hash
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 600000)
    return etag, key
