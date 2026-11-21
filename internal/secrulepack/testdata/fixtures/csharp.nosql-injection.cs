using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;

class UsersController : Controller
{
    private readonly IMongoCollection<BsonDocument> _users;

    public IActionResult Find([FromQuery] string name, [FromQuery] int age)
    {
        // ruleid: csharp.nosql-injection
        var a = _users.Find("{ name: '" + name + "' }").ToList();
        // ruleid: csharp.nosql-injection
        var b = _users.Find($"{{ name: '{name}' }}").ToList();
        // ok: csharp.nosql-injection
        var c = _users.Find(Builders<BsonDocument>.Filter.Eq("name", name)).ToList();
        // ok: csharp.nosql-injection
        var d = _users.Find($"{{ age: {{ $gt: {age} }} }}").ToList();
        return Ok(new[] { a, b, c, d });
    }

    public IActionResult Filter()
    {
        // ruleid: csharp.nosql-injection
        var filter = BsonDocument.Parse(Request.Query["filter"]);
        // ruleid: csharp.nosql-injection
        var scripted = new BsonDocument("$where", "this.owner == '" + Request.Query["owner"] + "'");
        return Ok(_users.Find(filter).ToList());
    }
}

// The program's own values, not request input.
class Seed
{
    BsonDocument Load(string json)
    {
        // ok: csharp.nosql-injection
        return BsonDocument.Parse(json);
    }
}
