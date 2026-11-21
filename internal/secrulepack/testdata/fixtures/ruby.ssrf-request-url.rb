require "net/http"
require "open-uri"

class PreviewsController < ApplicationController
  def show
    url = params[:url]
    # ruleid: ruby.ssrf-request-url
    body = Net::HTTP.get(URI(url))
    # ruleid: ruby.ssrf-request-url
    page = URI.open(params[:feed]).read
    # ruleid: ruby.ssrf-request-url
    resp = HTTParty.get(params[:callback])
    # ruleid: ruby.ssrf-request-url
    conn = Faraday.new(url: request.headers["X-Upstream"])
    # ruleid: ruby.ssrf-request-url
    RestClient.post("#{params[:hook]}/notify", {})
    render json: [body, page, resp, conn]
  end

  def safe
    # ok: ruby.ssrf-request-url
    body = Net::HTTP.get(URI("https://api.example.com/users/#{params[:id]}"))
    # ok: ruby.ssrf-request-url
    resp = HTTParty.get("https://api.example.com/search?q=#{CGI.escape(params[:q])}")
    # ok: ruby.ssrf-request-url
    page = HTTParty.get("https://api.example.com/v1/" + params[:path])
    # ok: ruby.ssrf-request-url
    status = HTTParty.get("https://status.example.com/health", query: { id: params[:id] })
    render json: [body, resp, page, status]
  end

  # The program's own values, not request input.
  def poll(endpoint)
    # ok: ruby.ssrf-request-url
    Net::HTTP.get(URI(endpoint))
  end
end
