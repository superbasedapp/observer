<?php

function import_feed()
{
    $xml = file_get_contents('php://input');
    $doc = new DOMDocument();
    // ruleid: php.xxe-parser
    $doc->loadXML($xml, LIBXML_NOENT | LIBXML_NONET);
    // ruleid: php.xxe-parser
    $feed = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_DTDLOAD);
    $reader = new XMLReader();
    $reader->XML($xml);
    // ruleid: php.xxe-parser
    $reader->setParserProperty(XMLReader::SUBST_ENTITIES, true);
    // ruleid: php.xxe-parser
    $doc->substituteEntities = true;
    // ruleid: php.xxe-parser
    libxml_disable_entity_loader(false);
    return [$doc, $feed];
}

function safe()
{
    $xml = file_get_contents('php://input');
    $doc = new DOMDocument();
    // ok: php.xxe-parser
    $doc->loadXML($xml, LIBXML_NONET);
    // ok: php.xxe-parser
    $feed = simplexml_load_string($xml);
    // ok: php.xxe-parser
    $doc->substituteEntities = false;
    // ok: php.xxe-parser
    libxml_disable_entity_loader(true);
    return [$doc, $feed];
}
