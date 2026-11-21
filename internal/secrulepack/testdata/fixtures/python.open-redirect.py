from django.http import HttpResponseRedirect
from django.shortcuts import redirect as dj_redirect
from django.utils.http import url_has_allowed_host_and_scheme
from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/login/done")
def login_done():
    target = request.args.get("next")
    # ruleid: python.open-redirect
    return redirect(target)


@app.route("/go")
def go():
    # ok: python.open-redirect
    a = redirect(url_for("profile", tab=request.args.get("tab")))
    # ok: python.open-redirect
    b = redirect("/items/" + request.args["id"])
    # ruleid: python.open-redirect
    c = redirect("/" + request.args["path"])
    return a or b or c


def django_done(request):
    target = request.GET.get("next", "/")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        # ok: python.open-redirect
        return HttpResponseRedirect(target)
    # ruleid: python.open-redirect
    return HttpResponseRedirect(request.POST["return_to"])


# The program's own values, not request input.
def go_home(target):
    # ok: python.open-redirect
    return redirect(target)
