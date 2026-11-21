import org.bson.Document
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.core.query.BasicQuery
import org.springframework.web.bind.annotation.*

@RestController
class AccountController(val mongoTemplate: MongoTemplate, val usersCollection: MongoCollection<Document>) {
    @PostMapping("/login")
    fun login(@RequestParam name: String): List<Document> {
        // ruleid: kotlin.nosql-injection
        return mongoTemplate.find(BasicQuery("{ name: '$name' }"), Document::class.java)
    }

    @GetMapping("/posts")
    fun posts(@RequestParam author: String) {
        // ruleid: kotlin.nosql-injection
        usersCollection.find(Document("\$where", "this.author == '$author'"))
        // ruleid: kotlin.nosql-injection
        usersCollection.find(Document.parse("{ author: '$author' }"))
    }

    @GetMapping("/kmongo")
    fun kmongo(@RequestParam name: String) {
        // ruleid: kotlin.nosql-injection
        usersCollection.findOne("{ name: '$name' }")
    }

    @GetMapping("/safe")
    fun safe(@RequestParam name: String, @RequestParam id: String) {
        // ok: kotlin.nosql-injection
        usersCollection.find(Filters.eq("name", name))
        // ok: kotlin.nosql-injection
        usersCollection.find(Document("_id", ObjectId(id)))
        // ok: kotlin.nosql-injection
        usersCollection.find(Document("name", name))
    }

    // The program's own values, not request input.
    fun purge(filter: String) {
        // ok: kotlin.nosql-injection
        usersCollection.deleteMany(Document.parse(filter))
    }
}
