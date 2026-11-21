import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import javax.xml.stream.XMLInputFactory

class Importer {
    fun parse(xml: java.io.InputStream) {
        // ruleid: kotlin.xxe-parser
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.isNamespaceAware = true
        dbf.newDocumentBuilder().parse(xml)
    }

    fun inline(xml: java.io.InputStream) {
        // ruleid: kotlin.xxe-parser
        SAXParserFactory.newInstance().newSAXParser().parse(xml, Handler())
    }

    fun applied(xml: java.io.InputStream) {
        // ruleid: kotlin.xxe-parser
        val dbf = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        dbf.newDocumentBuilder().parse(xml)
    }

    fun safe(xml: java.io.InputStream) {
        // ok: kotlin.xxe-parser
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        dbf.newDocumentBuilder().parse(xml)
    }

    fun safeApply(xml: java.io.InputStream) {
        // ok: kotlin.xxe-parser
        val dbf = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }
        dbf.newDocumentBuilder().parse(xml)
    }

    fun safeStax(xml: java.io.InputStream) {
        // ok: kotlin.xxe-parser
        val xif = XMLInputFactory.newInstance()
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false)
        xif.createXMLStreamReader(xml)
    }
}
