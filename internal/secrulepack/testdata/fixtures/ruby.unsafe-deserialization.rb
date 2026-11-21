require "base64"
require "yaml"

class StateController < ApplicationController
  def restore
    blob = Base64.decode64(params[:state])
    # ruleid: ruby.unsafe-deserialization
    @state = Marshal.load(blob)
    # ruleid: ruby.unsafe-deserialization
    @prefs = YAML.unsafe_load(cookies[:prefs])
    # ruleid: ruby.unsafe-deserialization
    @doc = YAML.load(request.body.read)
    # ruleid: ruby.unsafe-deserialization
    @obj = Oj.load(request.raw_post)
    # ruleid: ruby.unsafe-deserialization
    @cfg = JSON.load(params[:config])
    # ruleid: ruby.unsafe-deserialization
    @any = Oj.load(params[:payload], mode: :object)
  end

  def safe
    # ok: ruby.unsafe-deserialization
    @doc = YAML.safe_load(request.body.read)
    # ok: ruby.unsafe-deserialization
    @cfg = JSON.parse(params[:config])
    # ok: ruby.unsafe-deserialization
    @obj = Oj.load(request.raw_post, mode: :strict)
  end

  # The program's own values, not request input.
  def cached(path)
    # ok: ruby.unsafe-deserialization
    Marshal.load(File.binread(path))
  end
end
