using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that builds the command.
class AccountsController : Controller
{
    SqlCommand ByName(SqlConnection conn, string name)
    {
        // ruleid: csharp.sql-string-concat
        return new SqlCommand("SELECT * FROM Accounts WHERE Name = '" + name + "'", conn);
    }

    public IActionResult Lookup(SqlConnection conn)
    {
        return Ok(ByName(conn, Request.Query["name"]));
    }

    string RequestedOwner()
    {
        return Request.Headers["X-Owner"];
    }

    public IActionResult Owned(SqlConnection conn)
    {
        // ruleid: csharp.sql-string-concat
        return Ok(new SqlCommand("SELECT * FROM Accounts WHERE Owner = '" + RequestedOwner() + "'", conn));
    }

    // The sanitizer sits in the helper: the id is parsed to a number before
    // the caller builds the command.
    int AsId(string value)
    {
        return int.Parse(value);
    }

    public IActionResult ById(SqlConnection conn)
    {
        // ok: csharp.sql-string-concat
        return Ok(new SqlCommand("SELECT * FROM Accounts WHERE Id = " + AsId(Request.Query["id"]), conn));
    }
}
