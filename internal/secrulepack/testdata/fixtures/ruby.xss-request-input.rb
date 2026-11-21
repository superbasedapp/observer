class SearchController < ApplicationController
  helper_method :highlighted

  def show
    q = params[:q]
    # ruleid: ruby.xss-request-input
    @banner = "<p>Results for #{q}</p>".html_safe
    # ruleid: ruby.xss-request-input
    render html: "<h1>#{params[:title]}</h1>".html_safe
  end

  def preview
    # ruleid: ruby.xss-request-input
    render inline: "<div>#{cookies[:note]}</div>"
  end

  def highlighted
    # ruleid: ruby.xss-request-input
    view_context.raw(params[:snippet])
  end

  def safe
    # ok: ruby.xss-request-input
    @banner = "<p>Results for #{ERB::Util.html_escape(params[:q])}</p>".html_safe
    # ok: ruby.xss-request-input
    @body = sanitize(params[:body]).html_safe
    # ok: ruby.xss-request-input
    render plain: params[:q]
    # ok: ruby.xss-request-input
    @state = json_escape(params[:state].to_json).html_safe
  end

  # The program's own values, not request input.
  def badge(label)
    # ok: ruby.xss-request-input
    "<span class=\"badge\">#{label}</span>".html_safe
  end
end
