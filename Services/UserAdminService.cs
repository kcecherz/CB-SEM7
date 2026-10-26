using System.Security.Claims;
using Klucznik.Data;
using Klucznik.Security;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public sealed record UserListItem(
    int Id,
    string Login,
    string Role,
    bool IsBlocked,
    bool IsPermanentAdmin,
    bool MustChangePassword,
    bool IsOneTimePassword,
    DateTimeOffset? OneTimePasswordExpiresAt,
    DateTimeOffset PasswordChangedAt,
    DateTimeOffset CreatedAt);

public sealed record IssuedPassword(string Login, string Password, DateTimeOffset ExpiresAt);

public sealed record MutationResult(bool Succeeded, string? Error, IssuedPassword? Issued = null);

public sealed class UserAdminService(IDbContextFactory<AppDbContext> factory, PasswordHasher hasher)
{
    public async Task<IReadOnlyList<UserListItem>> ListAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        return await db.Users
            .AsNoTracking()
            .OrderBy(user => user.LoginNormalized)
            .Select(user => new UserListItem(
                user.Id,
                user.Login,
                user.Role,
                user.IsBlocked,
                user.IsPermanentAdmin,
                user.MustChangePassword,
                user.IsOneTimePassword,
                user.OneTimePasswordExpiresAt,
                user.PasswordChangedAt,
                user.CreatedAt))
            .ToListAsync();
    }

    public async Task<MutationResult> CreateAsync(ClaimsPrincipal actor, string? login, string? role)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (!await CanAsync(db, actor, Permission.ManageUsers))
            return Denied();

        var loginError = LoginRules.Validate(login);
        if (loginError is not null)
            return new MutationResult(false, loginError);

        if (!AccessCatalog.IsRole(role))
            return new MutationResult(false, "Wybierz rolę: administrator, redaktor albo czytelnik.");

        var normalized = LoginRules.Normalize(login!.Trim());
        if (await db.Users.AnyAsync(user => user.LoginNormalized == normalized))
            return new MutationResult(false, "Login jest już zajęty.");

        var now = DateTimeOffset.UtcNow;
        var expires = now.Add(OneTimePasswordFactory.Lifetime);
        var password = OneTimePasswordFactory.Generate();
        var account = new UserAccount
        {
            Login = login.Trim(),
            LoginNormalized = normalized,
            PasswordHash = hasher.Hash(password),
            Role = role!,
            MustChangePassword = true,
            IsOneTimePassword = true,
            OneTimePasswordExpiresAt = expires,
            PasswordChangedAt = now,
            CreatedAt = now,
        };
        db.Users.Add(account);
        await db.SaveChangesAsync();
        return new MutationResult(true, null, new IssuedPassword(account.Login, password, expires));
    }

    public async Task<MutationResult> UpdateAsync(ClaimsPrincipal actor, int userId, string? login, string? role)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (!await CanAsync(db, actor, Permission.ManageUsers))
            return Denied();

        var user = await db.Users.FirstOrDefaultAsync(item => item.Id == userId);
        if (user is null)
            return new MutationResult(false, "Nie znaleziono użytkownika.");

        var loginError = LoginRules.Validate(login);
        if (loginError is not null)
            return new MutationResult(false, loginError);

        if (!AccessCatalog.IsRole(role))
            return new MutationResult(false, "Wybierz rolę: administrator, redaktor albo czytelnik.");

        var trimmed = login!.Trim();
        var normalized = LoginRules.Normalize(trimmed);
        if (user.IsPermanentAdmin && (normalized != user.LoginNormalized || role != user.Role))
            return new MutationResult(false, "Stałego konta ADMIN nie można zmienić.");

        if (await db.Users.AnyAsync(item => item.Id != user.Id && item.LoginNormalized == normalized))
            return new MutationResult(false, "Login jest już zajęty.");

        if (ActorId(actor) == user.Id && role != user.Role)
            return new MutationResult(false, "Nie możesz zmienić własnej roli.");

        if (user.Role == AccessCatalog.Administrator && role != AccessCatalog.Administrator)
        {
            var error = await EnsureAnotherAdminAsync(db, user.Id);
            if (error is not null)
                return new MutationResult(false, error);
        }

        var roleChanged = user.Role != role;
        var loginChanged = user.LoginNormalized != normalized;
        user.Login = trimmed;
        user.LoginNormalized = normalized;
        user.Role = role!;
        if (roleChanged || loginChanged)
            await DropSessionsAsync(db, user.Id);

        await db.SaveChangesAsync();
        return new MutationResult(true, null);
    }

    public async Task<MutationResult> SetBlockedAsync(ClaimsPrincipal actor, int userId, bool blocked)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (!await CanAsync(db, actor, Permission.ManageUsers))
            return Denied();

        var user = await db.Users.FirstOrDefaultAsync(item => item.Id == userId);
        if (user is null)
            return new MutationResult(false, "Nie znaleziono użytkownika.");

        if (user.IsPermanentAdmin)
            return new MutationResult(false, "Stałego konta ADMIN nie można zablokować.");

        if (ActorId(actor) == user.Id)
            return new MutationResult(false, "Nie możesz zablokować własnego konta.");

        if (blocked && user.Role == AccessCatalog.Administrator)
        {
            var error = await EnsureAnotherAdminAsync(db, user.Id);
            if (error is not null)
                return new MutationResult(false, error);
        }

        user.IsBlocked = blocked;
        if (blocked)
            await DropSessionsAsync(db, user.Id);

        await db.SaveChangesAsync();
        return new MutationResult(true, null);
    }

    public async Task<MutationResult> DeleteAsync(ClaimsPrincipal actor, int userId)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (!await CanAsync(db, actor, Permission.ManageUsers))
            return Denied();

        var user = await db.Users.FirstOrDefaultAsync(item => item.Id == userId);
        if (user is null)
            return new MutationResult(false, "Nie znaleziono użytkownika.");

        if (user.IsPermanentAdmin)
            return new MutationResult(false, "Stałego konta ADMIN nie można usunąć.");

        if (ActorId(actor) == user.Id)
            return new MutationResult(false, "Nie możesz usunąć własnego konta.");

        if (user.Role == AccessCatalog.Administrator)
        {
            var error = await EnsureAnotherAdminAsync(db, user.Id);
            if (error is not null)
                return new MutationResult(false, error);
        }

        await DropSessionsAsync(db, user.Id);
        await db.PasswordHistory.Where(entry => entry.UserId == user.Id).ExecuteDeleteAsync();
        db.Users.Remove(user);
        await db.SaveChangesAsync();
        return new MutationResult(true, null);
    }

    public async Task<MutationResult> ResetPasswordAsync(ClaimsPrincipal actor, int userId)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (!await CanAsync(db, actor, Permission.ResetPasswords))
            return Denied();

        var user = await db.Users.FirstOrDefaultAsync(item => item.Id == userId);
        if (user is null)
            return new MutationResult(false, "Nie znaleziono użytkownika.");

        if (ActorId(actor) == user.Id)
            return new MutationResult(false, "Własne hasło zmień w formularzu zmiany hasła.");

        var now = DateTimeOffset.UtcNow;
        var expires = now.Add(OneTimePasswordFactory.Lifetime);
        var password = OneTimePasswordFactory.Generate();
        db.PasswordHistory.Add(new PasswordHistoryEntry
        {
            UserId = user.Id,
            PasswordHash = user.PasswordHash,
            CreatedAt = now,
        });
        user.PasswordHash = hasher.Hash(password);
        user.MustChangePassword = true;
        user.IsOneTimePassword = true;
        user.OneTimePasswordExpiresAt = expires;
        user.PasswordChangedAt = now;
        await DropSessionsAsync(db, user.Id);
        await db.SaveChangesAsync();
        await TrimHistoryAsync(db, user.Id);
        return new MutationResult(true, null, new IssuedPassword(user.Login, password, expires));
    }

    private static async Task TrimHistoryAsync(AppDbContext db, int userId)
    {
        var stale = (await db.PasswordHistory
            .Where(entry => entry.UserId == userId)
            .ToListAsync())
            .OrderByDescending(entry => entry.CreatedAt)
            .Skip(PasswordChangeService.HistoryLimit)
            .ToList();
        if (stale.Count == 0)
            return;

        db.PasswordHistory.RemoveRange(stale);
        await db.SaveChangesAsync();
    }

    private static async Task<string?> EnsureAnotherAdminAsync(AppDbContext db, int exceptUserId)
    {
        var otherAdmins = await db.Users.CountAsync(user =>
            user.Id != exceptUserId
            && user.Role == AccessCatalog.Administrator
            && !user.IsBlocked);
        return otherAdmins == 0
            ? "Musi zostać co najmniej jeden aktywny administrator."
            : null;
    }

    private static async Task DropSessionsAsync(AppDbContext db, int userId)
    {
        await db.Sessions.Where(session => session.UserId == userId).ExecuteDeleteAsync();
    }

    private static async Task<bool> CanAsync(AppDbContext db, ClaimsPrincipal principal, Permission permission)
    {
        var actor = await ActorAsync(db, principal);
        return actor is not null && AccessCatalog.Has(actor.Role, permission);
    }

    private static async Task<UserAccount?> ActorAsync(AppDbContext db, ClaimsPrincipal principal)
    {
        if (ActorId(principal) is not int id)
            return null;

        return await db.Users.AsNoTracking().FirstOrDefaultAsync(user => user.Id == id && !user.IsBlocked);
    }

    private static int? ActorId(ClaimsPrincipal principal) =>
        int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    private static MutationResult Denied() => new(false, "Brak uprawnień.");
}
