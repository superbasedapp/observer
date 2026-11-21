from bson import ObjectId
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["shop"]


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    # ruleid: python.nosql-injection
    user = db.users.find_one({"email": body["email"], "password": body["password"]})
    # ok: python.nosql-injection
    same = db.users.find_one({"email": str(body["email"])})
    # ok: python.nosql-injection
    by_id = db.users.find_one({"_id": ObjectId(body["id"])})
    return user or same or by_id


@app.route("/search")
def search():
    # ruleid: python.nosql-injection
    found = list(db["orders"].find(request.json))
    # ok: python.nosql-injection
    by_name = db.users.find_one({"name": request.args.get("name")})
    # ok: python.nosql-injection
    position = request.json["title"].find("x")
    return found, by_name, position


# The program's own values, not request input.
def by_email(email):
    # ok: python.nosql-injection
    return db.users.find_one({"email": email})
