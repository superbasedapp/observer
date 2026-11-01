from flask import Flask, request, render_template_string, render_template
from jinja2 import Environment, Template

app = Flask(__name__)
env = Environment()


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: python.template-injection
    page = render_template_string("<h1>Hello " + name + "</h1>")
    # ruleid: python.template-injection
    t = Template(request.form["tpl"])
    # ruleid: python.template-injection
    u = env.from_string(request.args["body"])
    # ok: python.template-injection
    safe = render_template_string("<h1>Hello {{ name }}</h1>", name=name)
    # ok: python.template-injection
    other = render_template("hello.html", name=name)
    return page + t.render() + u.render() + safe + other


# The false-positive shape of the 1.1.0 rule: request metadata the server
# controls (the method), not request input.
def describe():
    # ok: python.template-injection
    t = Template("Viewing {} page.".format(request.method))
    return t
