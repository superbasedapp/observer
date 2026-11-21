import com.fasterxml.jackson.databind.ObjectMapper
import com.thoughtworks.xstream.XStream
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import java.beans.XMLDecoder
import java.io.InputStream
import java.io.ObjectInputStream

class StateLoader {
    fun restore(input: InputStream): Any {
        // ruleid: kotlin.unsafe-deserialization
        return ObjectInputStream(input).readObject()
    }

    fun restoreNamed(input: InputStream): Any {
        val ois = ObjectInputStream(input)
        // ruleid: kotlin.unsafe-deserialization
        return ois.readObject()
    }

    fun restoreUse(input: InputStream): Any = ObjectInputStream(input).use { ois ->
        // ruleid: kotlin.unsafe-deserialization
        ois.readObject()
    }

    fun beans(input: InputStream): Any {
        // ruleid: kotlin.unsafe-deserialization
        return XMLDecoder(input).readObject()
    }

    fun xstream(xml: String): Any {
        val xs = XStream()
        // ruleid: kotlin.unsafe-deserialization
        return xs.fromXML(xml)
    }

    fun yaml(text: String): Any {
        // ruleid: kotlin.unsafe-deserialization
        return Yaml().load(text)
    }

    fun mapper(): ObjectMapper {
        val m = ObjectMapper()
        // ruleid: kotlin.unsafe-deserialization
        m.activateDefaultTyping(m.polymorphicTypeValidator)
        return m
    }

    fun filtered(input: InputStream): Any {
        val ois = ObjectInputStream(input)
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"))
        // ok: kotlin.unsafe-deserialization
        return ois.readObject()
    }

    fun safeYaml(text: String): Any {
        // ok: kotlin.unsafe-deserialization
        return Yaml(SafeConstructor(LoaderOptions())).load(text)
    }

    fun json(text: String): Any {
        // ok: kotlin.unsafe-deserialization
        return ObjectMapper().readValue(text, Map::class.java)
    }
}
