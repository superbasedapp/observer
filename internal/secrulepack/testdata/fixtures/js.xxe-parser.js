const libxmljs = require("libxmljs");

function parseUpload(req) {
  // ruleid: js.xxe-parser
  const doc = libxmljs.parseXml(req.body, { noent: true });
  // ok: js.xxe-parser
  const plain = libxmljs.parseXml(req.body);
  // ok: js.xxe-parser
  const off = libxmljs.parseXmlString(req.body, { noent: false, nonet: true });
  return [doc, plain, off];
}

function parseConfig(text) {
  // ruleid: js.xxe-parser
  return libxmljs.parseXmlString(text, { noblanks: true, noent: true });
}
