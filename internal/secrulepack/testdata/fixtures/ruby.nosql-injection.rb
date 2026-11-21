require "mongo"

class AccountsController < ApplicationController
  def login
    users = MONGO_CLIENT[:users]
    # ruleid: ruby.nosql-injection
    user = users.find(name: params[:name], password_digest: params[:digest]).first
    # ruleid: ruby.nosql-injection
    count = settings.db[:sessions].count_documents(token: cookies[:token])
    # ruleid: ruby.nosql-injection
    MONGO_CLIENT[:posts].find("$where" => "this.author == '#{params[:author]}'")
    # ruleid: ruby.nosql-injection
    @orders_collection.delete_many(params[:filter])
    render json: [user, count]
  end

  def safe
    users = MONGO_CLIENT[:users]
    # ok: ruby.nosql-injection
    user = users.find(name: params[:name].to_s).first
    # ok: ruby.nosql-injection
    post = MONGO_CLIENT[:posts].find(_id: BSON::ObjectId(params[:id])).first
    # ok: ruby.nosql-injection
    rows = User.where(name: params[:name])
    render json: [user, post, rows]
  end

  # The program's own values, not request input.
  def purge(filter)
    # ok: ruby.nosql-injection
    MONGO_CLIENT[:events].delete_many(filter)
  end
end
