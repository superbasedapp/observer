# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class FilesController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.path-traversal-request
    @a = File.read(File.join("/srv/files", wanted))
  end

  def show
    # ok: ruby.path-traversal-request
    @b = File.read(File.join("/srv/files", cleaned(params[:name])))
  end

  private

  def params_value
    params[:name]
  end

  def use_value(value)
    # ruleid: ruby.path-traversal-request
    File.read(File.join("/srv/files", value))
  end

  def wanted
    params[:name]
  end

  # The sanitizer sits in the helper.
  def cleaned(value)
    File.basename(value)
  end
end
