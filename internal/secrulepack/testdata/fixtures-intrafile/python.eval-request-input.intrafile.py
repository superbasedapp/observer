from flask import request

# Cross-function taint in one file (--taint-intrafile): the value from the
# web request is handed to a helper that runs it.


def run_expression(expr):
    # ruleid: python.eval-request-input
    return eval(expr)


def calculate():
    return run_expression(request.args.get("expr"))


def expression_from_request():
    return request.form["expr"]


def calculate_returned():
    # ruleid: python.eval-request-input
    return eval(expression_from_request())


# The helper takes the request value but returns a fixed expression; nothing
# of the input reaches eval.
def fixed_expression(_requested):
    return "1 + 1"


def calculate_fixed():
    # ok: python.eval-request-input
    return eval(fixed_expression(request.args.get("expr")))
