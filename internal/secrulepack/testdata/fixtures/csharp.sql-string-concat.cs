using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

class UserRepo
{
    void Find(SqlConnection conn, AppDb db, string name, int id)
    {
        // ruleid: csharp.sql-string-concat
        var a = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
        // ruleid: csharp.sql-string-concat
        db.Database.ExecuteSqlRaw($"DELETE FROM Users WHERE Id = {id}");
        // ruleid: csharp.sql-string-concat
        var b = db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");
        // ruleid: csharp.sql-string-concat
        var e = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);
        // ok: csharp.sql-string-concat
        var c = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        // ok: csharp.sql-string-concat
        db.Database.ExecuteSqlInterpolated($"DELETE FROM Users WHERE Id = {id}");
        // ok: csharp.sql-string-concat
        System.Console.WriteLine("SELECT * FROM Users WHERE Name = " + name);
    }
}

class Literal
{
    void Run(System.Data.IDbConnection conn, string name)
    {
        // ok: csharp.sql-string-concat
        var a = new SqlCommand("SELECT a FROM t" + " WHERE b = @b" + " AND c = @c", conn);
        // ruleid: csharp.sql-string-concat
        var b = new SqlCommand("SELECT a FROM t" + " WHERE b = '" + name + "'", conn);
    }
}
