import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;
import org.dom4j.io.SAXReader;
import org.w3c.dom.Document;

class XmlLoader {
    Document load(InputStream in) throws Exception {
        // ruleid: java.xxe-parser
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(in);
    }

    Document loadInline(InputStream in) throws Exception {
        // ruleid: java.xxe-parser
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
    }

    Document loadSafe(InputStream in) throws Exception {
        // ok: java.xxe-parser
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder().parse(in);
    }

    Object stream(InputStream in) throws Exception {
        // ruleid: java.xxe-parser
        XMLInputFactory xif = XMLInputFactory.newInstance();
        return xif.createXMLStreamReader(in);
    }

    Object streamSafe(InputStream in) throws Exception {
        // ok: java.xxe-parser
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        return xif.createXMLStreamReader(in);
    }

    Object sax(InputStream in) throws Exception {
        // ok: java.xxe-parser
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        return spf.newSAXParser();
    }

    Object transform() throws Exception {
        // ok: java.xxe-parser
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        return tf.newTransformer();
    }

    Object dom4j(InputStream in) throws Exception {
        // ruleid: java.xxe-parser
        SAXReader reader = new SAXReader();
        return reader.read(in);
    }

    Object dom4jSafe(InputStream in) throws Exception {
        SAXReader reader;
        // ok: java.xxe-parser
        reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return reader.read(in);
    }
}
