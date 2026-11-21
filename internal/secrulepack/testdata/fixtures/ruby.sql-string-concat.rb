class UsersController < ApplicationController
  def search
    name = params[:name]
    # ruleid: ruby.sql-string-concat
    @users = User.where("name = '#{name}'")
    # ruleid: ruby.sql-string-concat
    @more = User.order(params[:sort] + " DESC")
    # ruleid: ruby.sql-string-concat
    rows = ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = " + params[:id])
    # ruleid: ruby.sql-string-concat
    User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
    # ok: ruby.sql-string-concat
    @ok = User.where("name = ?", params[:name])
    # ok: ruby.sql-string-concat
    @ok2 = User.where(name: params[:name])
    # ok: ruby.sql-string-concat
    @ok5 = User.where(["token = ?", params[:token]]).first
    # ok: ruby.sql-string-concat
    @ok6 = User.where(name: "a").or(User.where(url: params[:url]))
    # ok: ruby.sql-string-concat
    @ok7 = User.find_by(params)
    # ok: ruby.sql-string-concat
    @ok3 = User.where("id = #{params[:id].to_i}")
    # ok: ruby.sql-string-concat
    @ok4 = User.where("name = #{User.connection.quote(params[:name])}")
    render json: [@users, @more, rows, @ok, @ok2, @ok3, @ok4]
  end

  def lookup
    conn = PG.connect(dbname: "app")
    # ruleid: ruby.sql-string-concat
    conn.exec("SELECT * FROM t WHERE c = '#{cookies[:pref]}'")
    # ruleid: ruby.sql-string-concat
    DB.fetch("SELECT * FROM t WHERE c = '#{request.params["c"]}'")
  end

  # The program's own values, not request input.
  def report(column)
    # ok: ruby.sql-string-concat
    User.where("#{column} IS NOT NULL")
  end
end
