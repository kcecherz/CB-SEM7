using System.Text;
using Klucznik.Security;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Data;

public static class DbSeeder
{
    public const string CardFileName = "karty-startowe.txt";

    public static async Task SeedAsync(AppDbContext db, PasswordHasher hasher, string dataDirectory)
    {
        if (!await db.Settings.AnyAsync())
        {
            db.Settings.Add(SecuritySettings.CreateDefault());
            await db.SaveChangesAsync();
        }

        var staleBefore = DateTimeOffset.UtcNow.AddHours(-12);
        var staleSessions = await db.Sessions.ToListAsync();
        var expired = staleSessions.Where(session => session.LastActivityAt < staleBefore).ToList();
        if (expired.Count > 0)
        {
            db.Sessions.RemoveRange(expired);
            await db.SaveChangesAsync();
        }

        if (await db.Users.AnyAsync())
            return;

        var now = DateTimeOffset.UtcNow;
        var expires = now.Add(OneTimePasswordFactory.Lifetime);
        var people = new (string Login, string Role, bool Permanent)[]
        {
            (AccessCatalog.PermanentLogin, AccessCatalog.Administrator, true),
            ("anna", AccessCatalog.Redaktor, false),
            ("bartek", AccessCatalog.Redaktor, false),
            ("celina", AccessCatalog.Czytelnik, false),
            ("dawid", AccessCatalog.Czytelnik, false),
        };

        var lines = new List<string>
        {
            "# Karty haseł jednorazowych z pierwszego uruchomienia.",
            "# Baza przechowuje wyłącznie skróty Argon2id. Ten plik jest jednorazowym wydaniem haseł.",
            "# login<TAB>hasło<TAB>rola<TAB>ważneDo",
        };

        foreach (var person in people)
        {
            var password = OneTimePasswordFactory.Generate();
            db.Users.Add(new UserAccount
            {
                Login = person.Login,
                LoginNormalized = LoginRules.Normalize(person.Login),
                PasswordHash = hasher.Hash(password),
                Role = person.Role,
                MustChangePassword = true,
                IsOneTimePassword = true,
                OneTimePasswordExpiresAt = expires,
                PasswordChangedAt = now,
                CreatedAt = now,
                IsPermanentAdmin = person.Permanent,
            });
            lines.Add($"{person.Login}\t{password}\t{person.Role}\t{expires:o}");
        }

        await db.SaveChangesAsync();
        Directory.CreateDirectory(dataDirectory);
        var path = Path.Combine(dataDirectory, CardFileName);
        await File.WriteAllLinesAsync(path, lines, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
    }
}

public sealed record IssuedCard(string Login, string Password, string Role, DateTimeOffset? ExpiresAt);

public static class BootstrapCards
{
    public static IReadOnlyList<IssuedCard> Read(string dataDirectory)
    {
        var path = Path.Combine(dataDirectory, DbSeeder.CardFileName);
        if (!File.Exists(path))
            return [];

        var cards = new List<IssuedCard>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                continue;

            var parts = line.Split('\t');
            if (parts.Length < 3)
                continue;

            DateTimeOffset? expires = null;
            if (parts.Length >= 4 && DateTimeOffset.TryParse(parts[3], out var parsed))
                expires = parsed;

            cards.Add(new IssuedCard(parts[0], parts[1], parts[2], expires));
        }

        return cards;
    }
}
