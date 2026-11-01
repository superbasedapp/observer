from Crypto.Cipher import AES, DES, ARC4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def seal(key, iv, data):
    # ruleid: python.weak-cipher
    a = DES.new(key, DES.MODE_CBC, iv)
    # ruleid: python.weak-cipher
    b = ARC4.new(key)
    # ruleid: python.weak-cipher
    c = AES.new(key, AES.MODE_ECB)
    # ruleid: python.weak-cipher
    d = Cipher(algorithms.AES(key), modes.ECB())
    # ok: python.weak-cipher
    e = AES.new(key, AES.MODE_GCM)
    # ok: python.weak-cipher
    f = Cipher(algorithms.AES(key), modes.GCM(iv))
    return a, b, c, d, e, f
