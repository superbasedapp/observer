import html

from django.http import HttpResponse
from django.utils.safestring import mark_safe
from flask import Flask, request, render_template
from markupsafe import Markup, escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: python.xss-request-input
    banner = Markup("<b>Hello " + name + "</b>")
    # ok: python.xss-request-input
    safe_banner = Markup("<b>Hello %s</b>") % name
    # ok: python.xss-request-input
    escaped = Markup("<b>Hello " + str(escape(name)) + "</b>")
    # ok: python.xss-request-input
    page = Markup(render_template("hello.html", name=name))
    return banner + safe_banner + escaped + page


def profile(request):
    bio = request.POST["bio"]
    # ruleid: python.xss-request-input
    note = mark_safe("<p>" + bio + "</p>")
    # ruleid: python.xss-request-input
    return HttpResponse("<h1>" + request.GET.get("title", "") + "</h1>")


def profile_text(request):
    bio = request.POST["bio"]
    # ok: python.xss-request-input
    a = HttpResponse(bio, content_type="text/plain")
    # ok: python.xss-request-input
    b = HttpResponse("<p>" + html.escape(bio) + "</p>")
    return a or b


# The program's own values, not request input.
def badge(label):
    # ok: python.xss-request-input
    return mark_safe("<span class=badge>" + label + "</span>")
