import com.fasterxml.jackson.databind.ObjectMapper;
import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputStream;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

class Loader {
    Object load(InputStream in, String doc) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: java.unsafe-deserialization
        Object a = ois.readObject();
        // ruleid: java.unsafe-deserialization
        Object b = new XMLDecoder(in).readObject();
        // ruleid: java.unsafe-deserialization
        Object c = new Yaml().load(doc);
        ObjectMapper m = new ObjectMapper();
        // ruleid: java.unsafe-deserialization
        m.enableDefaultTyping();
        // ok: java.unsafe-deserialization
        Object d = new Yaml(new SafeConstructor(new LoaderOptions())).load(doc);
        // ok: java.unsafe-deserialization
        Object e = m.readValue(doc, Object.class);
        return new Object[]{a, b, c, d, e};
    }

    Object filtered(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(info -> java.io.ObjectInputFilter.Status.REJECTED);
        // ok: java.unsafe-deserialization
        return ois.readObject();
    }
}
