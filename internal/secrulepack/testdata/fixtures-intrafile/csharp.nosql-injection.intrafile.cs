using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that parses it as a query document.
class FiltersController : Controller
{
    BsonDocument AsFilter(string json)
    {
        // ruleid: csharp.nosql-injection
        return BsonDocument.Parse(json);
    }

    public IActionResult Search()
    {
        return Ok(AsFilter(Request.Query["filter"]));
    }

    string RequestedOwner()
    {
        return Request.Form["owner"];
    }

    public IActionResult Owned()
    {
        // ruleid: csharp.nosql-injection
        return Ok(new BsonDocument("$where", "this.owner == '" + RequestedOwner() + "'"));
    }

    // The sanitizer sits in the helper: the age is parsed to a number before
    // the caller builds the query document.
    int AsAge(string value)
    {
        return int.Parse(value);
    }

    public IActionResult Older()
    {
        // ok: csharp.nosql-injection
        return Ok(BsonDocument.Parse("{ age: { $gt: " + AsAge(Request.Query["age"]) + " } }"));
    }
}
