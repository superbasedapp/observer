import pickle
import socket

import yaml
from flask import request


def restore():
    # ruleid: python.unsafe-deserialization
    state = pickle.loads(request.data)
    # ruleid: python.unsafe-deserialization
    cfg = yaml.load(request.files["config"].read(), Loader=yaml.Loader)
    # ok: python.unsafe-deserialization
    safe = yaml.load(request.get_data(), Loader=yaml.SafeLoader)
    return state, cfg, safe


def serve(sock: socket.socket):
    blob = sock.recv(65536)
    # ruleid: python.unsafe-deserialization
    return pickle.loads(blob)


# The false-positive shapes of the 1.1.0 rule: data the program wrote
# itself (a cache, a round trip in memory).
def cache_roundtrip(obj, path):
    copy = pickle.loads(pickle.dumps(obj))
    with open(path, "rb") as f:
        # ok: python.unsafe-deserialization
        cached = pickle.load(f)
    # ok: python.unsafe-deserialization
    again = pickle.loads(pickle.dumps(copy))
    return cached, again
