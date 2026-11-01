from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    # ruleid: python.eval-request-input
    return str(eval(expr))


@app.route("/run", methods=["POST"])
def run():
    code = request.form["code"]
    # ruleid: python.eval-request-input
    exec(code)
    return "ok"


@app.route("/fixed")
def fixed():
    name = request.args.get("name")
    # ok: python.eval-request-input
    return str(eval("1 + 2"))


def local_tool(expr):
    # ok: python.eval-request-input
    return eval(compile(expr, "<cfg>", "eval"))
