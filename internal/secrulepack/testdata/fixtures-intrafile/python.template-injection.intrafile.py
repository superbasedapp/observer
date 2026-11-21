from flask import render_template_string, request


def render_page(source):
    # ruleid: python.template-injection
    return render_template_string(source)


def page():
    return render_page(request.args.get("tpl"))


def requested_template():
    return request.form["tpl"]


def page_returned():
    # ruleid: python.template-injection
    return render_template_string(requested_template())


# The helper takes the request value but returns a fixed template; nothing
# of the input becomes template source.
def fixed_template(_requested):
    return "<p>{{ name }}</p>"


def page_fixed():
    # ok: python.template-injection
    return render_template_string(fixed_template(request.args.get("tpl")), name="x")
