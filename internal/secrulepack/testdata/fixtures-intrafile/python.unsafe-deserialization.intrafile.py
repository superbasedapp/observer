import pickle

from flask import request


def restore(blob):
    # ruleid: python.unsafe-deserialization
    return pickle.loads(blob)


def load_state():
    return restore(request.get_data())


def socket_payload(sock):
    return sock.recv(4096)


def load_from_socket(sock):
    # ruleid: python.unsafe-deserialization
    return pickle.loads(socket_payload(sock))


# The helper takes the request body but returns a fixed byte string
# (a stored default); nothing of the input is deserialized.
def default_state(_body):
    return b"\x80\x04N."


def load_default():
    # ok: python.unsafe-deserialization
    return pickle.loads(default_state(request.get_data()))
