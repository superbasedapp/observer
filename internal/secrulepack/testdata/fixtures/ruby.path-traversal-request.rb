require "fileutils"

class DownloadsController < ApplicationController
  BASE = "/srv/uploads"

  def show
    name = params[:name]
    # ruleid: ruby.path-traversal-request
    send_file File.join(BASE, name)
    # ruleid: ruby.path-traversal-request
    data = File.read("#{BASE}/#{params[:file]}")
    # ruleid: ruby.path-traversal-request
    File.open(Rails.root.join("storage", params[:path]), "rb") { |f| f.read }
    # ruleid: ruby.path-traversal-request
    FileUtils.rm_rf(BASE + "/" + cookies[:workspace])
    # ruleid: ruby.path-traversal-request
    lines = IO.readlines(request.params["log"])
    # ruleid: ruby.path-traversal-request
    render file: "/srv/pages/#{params[:page]}"
    [data, lines]
  end

  def safe
    # ok: ruby.path-traversal-request
    send_file File.join(BASE, File.basename(params[:name]))
    # ok: ruby.path-traversal-request
    data = File.read("#{BASE}/report-#{params[:id].to_i}.csv")
    # ok: ruby.path-traversal-request
    File.write(File.join(BASE, "upload.bin"), params[:body])
    # ok: ruby.path-traversal-request
    File.open(File.join(BASE, "index.json")).read
    data
  end

  # The program's own values, not request input.
  def cleanup(dir)
    # ok: ruby.path-traversal-request
    FileUtils.rm_rf(File.join(BASE, dir))
  end
end
