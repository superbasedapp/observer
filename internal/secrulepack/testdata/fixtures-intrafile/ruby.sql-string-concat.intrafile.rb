# Cross-function taint in one file (--taint-intrafile): the request value is
# handed to a helper that pastes it into SQL, or a helper returns it.
class ReportsController < ApplicationController
  def index
    by_name(params[:name])
    # ruleid: ruby.sql-string-concat
    @rows = User.where("email = '#{wanted_email}'")
  end

  def show
    # ok: ruby.sql-string-concat
    @rows = User.where("id = #{numeric(params[:id])}")
  end

  private

  def by_name(name)
    # ruleid: ruby.sql-string-concat
    User.where("name = '#{name}'")
  end

  def wanted_email
    params[:email]
  end

  # The sanitizer sits in the helper.
  def numeric(value)
    value.to_i
  end
end
