using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;

class Loader
{
    object Load(Stream s, string json)
    {
        // ruleid: csharp.unsafe-deserialization
        var f = new BinaryFormatter();
        // ruleid: csharp.unsafe-deserialization
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        // ok: csharp.unsafe-deserialization
        var plain = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        // ok: csharp.unsafe-deserialization
        var o = System.Text.Json.JsonSerializer.Deserialize<object>(json);
        return f.Deserialize(s) ?? JsonConvert.DeserializeObject(json, settings) ?? plain ?? o;
    }
}
