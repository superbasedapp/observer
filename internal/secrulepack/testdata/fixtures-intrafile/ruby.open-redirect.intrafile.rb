# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class ReturnsController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.open-redirect
    @a = redirect_to wanted
  end

  def show
    # ok: ruby.open-redirect
    @b = redirect_to cleaned(params[:return_to])
  end

  private

  def params_value
    params[:return_to]
  end

  def use_value(value)
    # ruleid: ruby.open-redirect
    redirect_to value
  end

  def wanted
    params[:return_to]
  end

  # The sanitizer sits in the helper.
  def cleaned(value)
    CGI.escape(value)
  end
end
