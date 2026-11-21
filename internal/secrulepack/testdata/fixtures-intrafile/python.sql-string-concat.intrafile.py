from flask import request


def find_user(cursor, name):
    # ruleid: python.sql-string-concat
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def lookup(cursor):
    find_user(cursor, request.args.get("name"))


def requested_name():
    return request.form["name"]


def lookup_returned(cursor):
    # ruleid: python.sql-string-concat
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % requested_name())


# The sanitizer sits in the helper: the id is parsed to an integer before
# the caller builds the statement.
def as_id(value):
    return int(value)


def lookup_by_id(cursor):
    # ok: python.sql-string-concat
    cursor.execute("SELECT * FROM users WHERE id = " + str(as_id(request.args.get("id"))))
