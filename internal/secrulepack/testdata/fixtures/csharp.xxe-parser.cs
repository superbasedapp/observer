using System.IO;
using System.Xml;

class XmlLoader
{
    XmlDocument Load(Stream input)
    {
        var doc = new XmlDocument();
        // ruleid: csharp.xxe-parser
        doc.XmlResolver = new XmlUrlResolver();
        doc.Load(input);
        return doc;
    }

    XmlReader Reader(Stream input)
    {
        // ruleid: csharp.xxe-parser
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        return XmlReader.Create(input, settings);
    }

    XmlReader ReaderSet(Stream input)
    {
        var settings = new XmlReaderSettings();
        // ruleid: csharp.xxe-parser
        settings.DtdProcessing = DtdProcessing.Parse;
        return XmlReader.Create(input, settings);
    }

    XmlReader ReaderSafe(Stream input)
    {
        // ok: csharp.xxe-parser
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
        return XmlReader.Create(input, settings);
    }

    XmlReader ReaderNoResolver(Stream input)
    {
        // ok: csharp.xxe-parser
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null };
        return XmlReader.Create(input, settings);
    }

    XmlReader ReaderNoResolverSet(Stream input)
    {
        var settings = new XmlReaderSettings();
        // ok: csharp.xxe-parser
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = null;
        return XmlReader.Create(input, settings);
    }

    XmlDocument LoadSafe(Stream input)
    {
        // ok: csharp.xxe-parser
        var doc = new XmlDocument { XmlResolver = null };
        doc.Load(input);
        return doc;
    }
}
