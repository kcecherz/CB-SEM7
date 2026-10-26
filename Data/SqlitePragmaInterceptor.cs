using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Klucznik.Data;

public sealed class SqlitePragmaInterceptor : DbConnectionInterceptor
{
    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        base.ConnectionOpened(connection, eventData);
        Apply(connection);
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        await base.ConnectionOpenedAsync(connection, eventData, cancellationToken);
        await ApplyAsync(connection, cancellationToken);
    }

    private static void Apply(DbConnection connection)
    {
        using var busy = connection.CreateCommand();
        busy.CommandText = "PRAGMA busy_timeout = 5000;";
        busy.ExecuteNonQuery();

        using var foreignKeys = connection.CreateCommand();
        foreignKeys.CommandText = "PRAGMA foreign_keys = ON;";
        foreignKeys.ExecuteNonQuery();
    }

    private static async Task ApplyAsync(DbConnection connection, CancellationToken cancellationToken)
    {
        await using var busy = connection.CreateCommand();
        busy.CommandText = "PRAGMA busy_timeout = 5000;";
        await busy.ExecuteNonQueryAsync(cancellationToken);

        await using var foreignKeys = connection.CreateCommand();
        foreignKeys.CommandText = "PRAGMA foreign_keys = ON;";
        await foreignKeys.ExecuteNonQueryAsync(cancellationToken);
    }
}
