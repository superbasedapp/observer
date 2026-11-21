# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class JobsController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.shell-interpolation
    @a = system("convert #{wanted} out.png")
  end

  def show
    # ok: ruby.shell-interpolation
    @b = system("convert #{cleaned(params[:file])} out.png")
  end

  private

  def params_value
    params[:file]
  end

  def use_value(value)
    # ruleid: ruby.shell-interpolation
    system("convert #{value} out.png")
  end

  def wanted
    params[:file]
  end

  # The sanitizer sits in the helper.
  def cleaned(value)
    Shellwords.escape(value)
  end
end
