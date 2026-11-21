# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that holds the sink, or a helper returns it.
class MembersController < ApplicationController
  def index
    use_value(params_value)
    # ruleid: ruby.nosql-injection
    @a = MONGO_CLIENT[:members].find(name: wanted)
  end

  def show
    # ok: ruby.nosql-injection
    @b = MONGO_CLIENT[:members].find(name: cleaned(params[:name]))
  end

  private

  def params_value
    params[:name]
  end

  def use_value(value)
    # ruleid: ruby.nosql-injection
    MONGO_CLIENT[:members].find(name: value)
  end

  def wanted
    params[:name]
  end

  # The sanitizer sits in the helper.
  def cleaned(value)
    value.to_s
  end
end
