import html

from django.http import HttpResponse
from django.utils.safestring import mark_safe
from flask import request


# Cross-function taint in one file (--taint-intrafile): the value from the
# web request is handed to a helper that marks it safe.
def as_heading(text):
    # ruleid: python.xss-request-input
    return mark_safe("<h1>" + text + "</h1>")


def heading():
    return as_heading(request.args.get("title"))


def requested_note(request):
    return request.GET.get("note", "")


def note(request):
    # ruleid: python.xss-request-input
    return HttpResponse("<p>" + requested_note(request) + "</p>")


# The sanitizer sits in the helper: the value is escaped before the caller
# marks it safe.
def escaped(value):
    return html.escape(value)


def comment():
    # ok: python.xss-request-input
    return mark_safe("<p>" + escaped(request.form["comment"]) + "</p>")
