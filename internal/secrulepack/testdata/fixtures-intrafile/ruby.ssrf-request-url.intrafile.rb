# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class FetchController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.ssrf-request-url
    @a = Net::HTTP.get(URI(wanted))
  end

  def show
    # ok: ruby.ssrf-request-url
    @b = Net::HTTP.get(URI(cleaned(params[:url])))
  end

  private

  def params_value
    params[:url]
  end

  def use_value(value)
    # ruleid: ruby.ssrf-request-url
    Net::HTTP.get(URI(value))
  end

  def wanted
    params[:url]
  end

  # The sanitizer sits in the helper.
  def cleaned(value)
    CGI.escape(value)
  end
end
