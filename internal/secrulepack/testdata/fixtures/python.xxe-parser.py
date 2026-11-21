import xml.sax
from xml.sax import handler

import defusedxml.ElementTree as safe_et
from lxml import etree


def load(data):
    # ruleid: python.xxe-parser
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)


def load_remote(data):
    # ruleid: python.xxe-parser
    parser = etree.XMLParser(load_dtd=True, no_network=False)
    return etree.fromstring(data, parser)


def load_safe(data):
    # ok: python.xxe-parser
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(data, parser)


def load_defused(data):
    # ok: python.xxe-parser
    return safe_et.fromstring(data)


def sax_parse(path, content_handler):
    reader = xml.sax.make_parser()
    # ruleid: python.xxe-parser
    reader.setFeature(handler.feature_external_ges, True)
    # ok: python.xxe-parser
    reader.setFeature(handler.feature_namespaces, True)
    reader.setContentHandler(content_handler)
    reader.parse(path)
