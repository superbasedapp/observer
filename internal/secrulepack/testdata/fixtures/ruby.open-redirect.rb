class SessionsController < ApplicationController
  def create
    target = params[:return_to]
    # ruleid: ruby.open-redirect
    redirect_to target
  end

  def back
    # ruleid: ruby.open-redirect
    redirect_back fallback_location: params[:fallback]
  end

  def cookie
    # ruleid: ruby.open-redirect
    redirect_to "#{cookies[:origin]}/welcome"
  end

  def safe
    # ok: ruby.open-redirect
    redirect_to "/items/#{params[:id]}"
    # ok: ruby.open-redirect
    redirect_to params[:return_to], allow_other_host: false
    # ok: ruby.open-redirect
    redirect_to url_for(controller: "items", action: "show", id: params[:id])
    # ok: ruby.open-redirect
    redirect_to "https://shop.example.com/cart?item=#{params[:item]}"
    # ok: ruby.open-redirect
    redirect_to edit_admin_item_path(params[:id])
    item = Item.find(params[:id])
    # ok: ruby.open-redirect
    redirect_to item
  end

  # The program's own values, not request input.
  def home(path)
    # ok: ruby.open-redirect
    redirect_to path
  end
end

# Sinatra.
class App < Sinatra::Base
  get "/out" do
    # ruleid: ruby.open-redirect
    redirect params["u"]
  end

  get "/in" do
    # ok: ruby.open-redirect
    redirect "/dashboard?tab=#{params["tab"]}"
  end
end
