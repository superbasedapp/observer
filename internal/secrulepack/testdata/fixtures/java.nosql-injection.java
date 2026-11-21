import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import javax.servlet.http.HttpServletRequest;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class UserSearch {
    MongoTemplate mongoTemplate;
    MongoCollection<Document> users;

    @GetMapping("/users")
    Object find(@RequestParam String name, @RequestParam int age) {
        // ruleid: java.nosql-injection
        BasicQuery q = new BasicQuery("{ name: '" + name + "' }");
        // ok: java.nosql-injection
        Query typed = new Query(Criteria.where("name").is(name));
        // ok: java.nosql-injection
        BasicQuery fixed = new BasicQuery("{ age: { $gt: " + age + " } }");
        return mongoTemplate.find(q, Object.class);
    }

    Object filter(HttpServletRequest request) {
        // ruleid: java.nosql-injection
        Document doc = Document.parse(request.getParameter("filter"));
        // ruleid: java.nosql-injection
        Object scripted = users.find(Filters.where("this.owner == '" + request.getParameter("owner") + "'"));
        // ok: java.nosql-injection
        Object plain = users.find(Filters.eq("owner", request.getParameter("owner")));
        return users.find(doc);
    }
}

// The program's own values, not request input.
class Seed {
    Document load(String json) {
        // ok: java.nosql-injection
        return Document.parse(json);
    }
}
