# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class PagesController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.xss-request-input
    @a = "<p>#{wanted}</p>".html_safe
  end

  def show
    # ok: ruby.xss-request-input
    @b = "<p>#{cleaned(params[:title])}</p>".html_safe
  end

  private

  def params_value
    params[:title]
  end

  def use_value(value)
    # ruleid: ruby.xss-request-input
    "<p>#{value}</p>".html_safe
  end

  def wanted
    params[:title]
  end

  # The sanitizer sits in the helper.
  def cleaned(value)
    ERB::Util.html_escape(value)
  end
end
