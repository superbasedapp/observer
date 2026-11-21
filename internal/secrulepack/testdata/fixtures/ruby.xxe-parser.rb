require "nokogiri"

class ImportsController < ApplicationController
  def create
    xml = request.body.read
    # ruleid: ruby.xxe-parser
    doc = Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::DEFAULT_XML | Nokogiri::XML::ParseOptions::NOENT)
    # ruleid: ruby.xxe-parser
    other = Nokogiri::XML(xml) { |config| config.strict.noent }
    feed = Nokogiri::XML(xml) do |config|
      # ruleid: ruby.xxe-parser
      config.dtdload
    end
    render json: [doc, other, feed]
  end

  def libxml
    # ruleid: ruby.xxe-parser
    LibXML::XML.default_substitute_entities = true
    # ruleid: ruby.xxe-parser
    LibXML::XML::Parser.string(request.raw_post, options: LibXML::XML::Parser::Options::NOENT).parse
  end

  def safe
    xml = request.body.read
    # ok: ruby.xxe-parser
    doc = Nokogiri::XML(xml)
    # ok: ruby.xxe-parser
    strict = Nokogiri::XML(xml) { |config| config.strict.nonet }
    # ok: ruby.xxe-parser
    opts = Nokogiri::XML::ParseOptions::DEFAULT_XML | Nokogiri::XML::ParseOptions::NONET
    # ok: ruby.xxe-parser
    LibXML::XML.default_substitute_entities = false
    render json: [doc, strict, opts]
  end
end
