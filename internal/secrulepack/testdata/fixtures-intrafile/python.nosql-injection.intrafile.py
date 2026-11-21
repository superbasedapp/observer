from flask import request
from pymongo import MongoClient

db = MongoClient()["shop"]


# Cross-function taint in one file (--taint-intrafile): the value from the
# web request is handed to a helper that queries with it.
def by_email(email):
    # ruleid: python.nosql-injection
    return db.users.find_one({"email": email})


def login():
    return by_email(request.json["email"])


def requested_filter():
    return request.get_json()["filter"]


def search():
    # ruleid: python.nosql-injection
    return list(db.orders.find(requested_filter()))


# The sanitizer sits in the helper: the value is converted to a string
# before the caller queries with it.
def as_text(value):
    return str(value)


def lookup():
    # ok: python.nosql-injection
    return db.users.find_one({"name": as_text(request.json["name"])})
