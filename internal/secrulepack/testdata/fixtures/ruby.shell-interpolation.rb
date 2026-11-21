require "open3"
require "shellwords"

class ArchivesController < ApplicationController
  def create
    dir = params[:dir]
    # ruleid: ruby.shell-interpolation
    system("tar czf /tmp/out.tgz #{dir}")
    # ruleid: ruby.shell-interpolation
    listing = `ls -la #{params[:path]}`
    # ruleid: ruby.shell-interpolation
    out = %x(du -sh #{params[:path]})
    # ruleid: ruby.shell-interpolation
    stdout, status = Open3.capture2("grep -r " + params[:q] + " /srv/data")
    # ruleid: ruby.shell-interpolation
    IO.popen("convert #{params[:file]} out.png")
    # ruleid: ruby.shell-interpolation
    system("sh", "-c", "ping -c 1 #{params[:host]}")
    # ruleid: ruby.shell-interpolation
    pid = Process.spawn({ "LANG" => "C" }, "zip -r out.zip #{cookies[:folder]}")
    render plain: [listing, out, stdout, status, pid].join
  end

  def safe
    # ok: ruby.shell-interpolation
    system("tar", "czf", "/tmp/out.tgz", params[:dir])
    # ok: ruby.shell-interpolation
    Open3.capture2("grep", "-r", params[:q], "/srv/data")
    # ok: ruby.shell-interpolation
    system("cat", params[:file])
    # ok: ruby.shell-interpolation
    IO.popen(["convert", params[:file], "out.png"])
    # ok: ruby.shell-interpolation
    system("ls -la #{Shellwords.escape(params[:path])}")
    # ok: ruby.shell-interpolation
    system("kill -HUP #{params[:pid].to_i}")
    # ok: ruby.shell-interpolation
    stdout, status = Open3.capture2("sort", stdin_data: params[:text])
    head :ok
  end

  # The program's own values, not request input.
  def rotate(path)
    # ok: ruby.shell-interpolation
    system("logrotate #{path}")
    # ok: ruby.shell-interpolation
    `git rev-parse HEAD`
  end
end
