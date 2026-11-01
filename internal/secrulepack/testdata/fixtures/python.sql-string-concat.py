import sqlite3

from flask import request

TABLE = "notes"


def search(conn: sqlite3.Connection):
    cur = conn.cursor()
    term = request.args.get("q")
    # ruleid: python.sql-string-concat
    cur.execute("SELECT * FROM notes WHERE body LIKE '%" + term + "%'")
    # ruleid: python.sql-string-concat
    cur.execute(f"DELETE FROM notes WHERE owner = '{request.form['owner']}'")
    sql = "UPDATE notes SET tag = '%s'" % request.json["tag"]
    # ruleid: python.sql-string-concat
    cur.execute(sql)
    # ok: python.sql-string-concat
    cur.execute("SELECT * FROM notes WHERE body LIKE ?", ("%" + term + "%",))
    limit = int(request.args.get("limit", "10"))
    # ok: python.sql-string-concat
    cur.execute("SELECT * FROM notes LIMIT %d" % limit)


def internal(conn: sqlite3.Connection, columns, ids):
    cur = conn.cursor()
    marks = ",".join("?" for _ in ids)
    # ok: python.sql-string-concat
    cur.execute(f"SELECT {', '.join(columns)} FROM {TABLE} WHERE id IN ({marks})", ids)
    # ok: python.sql-string-concat
    cur.executescript("DROP TABLE IF EXISTS " + TABLE + "_old;")


# SEC-G5 near misses: an execute that is not SQL (a GraphQL schema or test
# client run with request input, the shape behind the G4 corpus's ten false
# positives).
def graphql_view(schema, client):
    # ok: python.sql-string-concat
    result = schema.execute(request.json["query"])
    # ok: python.sql-string-concat
    client.execute(request.form["query"])
    return result


def raw_django(Note):
    # ruleid: python.sql-string-concat
    return Note.objects.raw("SELECT * FROM notes WHERE owner = '" + request.GET["owner"] + "'")
