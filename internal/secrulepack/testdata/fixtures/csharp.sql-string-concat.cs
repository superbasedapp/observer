using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Dapper;

class UserController : Controller
{
    private readonly SqlConnection _connection;
    private readonly AppDb db;

    public IActionResult Find(SqlConnection conn)
    {
        string name = Request.Query["name"];
        // ruleid: csharp.sql-string-concat
        var a = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
        // ruleid: csharp.sql-string-concat
        db.Database.ExecuteSqlRaw($"DELETE FROM Users WHERE Name = '{name}'");
        // ruleid: csharp.sql-string-concat
        var b = db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");
        // ruleid: csharp.sql-string-concat
        var n = db.Database.SqlQueryRaw<int>("SELECT COUNT(*) FROM Users WHERE Name = '" + name + "'");
        var cmd = conn.CreateCommand();
        // ruleid: csharp.sql-string-concat
        cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + Request.Form["owner"] + "'";
        // ok: csharp.sql-string-concat
        var c = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        // ok: csharp.sql-string-concat
        db.Database.ExecuteSqlInterpolated($"DELETE FROM Users WHERE Name = {name}");
        // ok: csharp.sql-string-concat
        System.Console.WriteLine("SELECT * FROM Users WHERE Name = " + name);
        int id = int.Parse(Request.Query["id"]);
        // ok: csharp.sql-string-concat
        var d = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);
        return Ok();
    }

    public IActionResult Search([FromQuery] string term, [FromQuery] int page)
    {
        string sql = "SELECT * FROM Users WHERE Name LIKE '%" + term + "%'";
        // ruleid: csharp.sql-string-concat
        var rows = _connection.Query<User>(sql);
        // ok: csharp.sql-string-concat
        var paged = _connection.Query<User>($"SELECT * FROM Users ORDER BY Id OFFSET {page * 20} ROWS");
        // ok: csharp.sql-string-concat
        var safe = _connection.Query<User>("SELECT * FROM Users WHERE Name LIKE @term", new { term });
        return Ok(rows);
    }
}

// The program's own values, not request input (the 1.3.1 corpus shapes).
class Migrations
{
    void Run(SqlConnection conn, string table, int id)
    {
        // ok: csharp.sql-string-concat
        var a = new SqlCommand("SELECT a FROM " + table + " WHERE b = @b", conn);
        // ok: csharp.sql-string-concat
        var e = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);
    }
}
