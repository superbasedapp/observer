# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class StatesController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.unsafe-deserialization
    @a = Marshal.load(wanted)
  end

  def show
    # ok: ruby.unsafe-deserialization
    @b = Marshal.load(cleaned(cookies[:state]))
  end

  private

  def params_value
    cookies[:state]
  end

  def use_value(value)
    # ruleid: ruby.unsafe-deserialization
    Marshal.load(value)
  end

  def wanted
    cookies[:state]
  end

  # No sanitizer exists for this sink: the helper ignores its input and
  # returns the program's own value.
  def cleaned(value)
    DEFAULT_STATE
  end
end
