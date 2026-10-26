using System.Security.Claims;
using Klucznik.Data;
using Klucznik.Security;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public sealed record PasswordChangeOutcome(bool Succeeded, string? Error);

public sealed class PasswordChangeService(IDbContextFactory<AppDbContext> factory, PasswordHasher hasher)
{
    public const int HistoryLimit = 8;

    public async Task<UserAccount?> FindAsync(ClaimsPrincipal principal)
    {
        if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            return null;

        await using var db = await factory.CreateDbContextAsync();
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(user => user.Id == userId);
    }

    public async Task<PasswordChangeOutcome> ChangeAsync(
        ClaimsPrincipal principal,
        string? currentPassword,
        string? newPassword,
        string? confirmPassword)
    {
        var current = currentPassword ?? "";
        var next = newPassword ?? "";
        var confirm = confirmPassword ?? "";

        if (!string.Equals(next, confirm, StringComparison.Ordinal))
            return new PasswordChangeOutcome(false, "Nowe hasło i jego powtórzenie muszą być identyczne.");

        if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            return new PasswordChangeOutcome(false, "Sesja jest nieprawidłowa. Zaloguj się ponownie.");

        await using var db = await factory.CreateDbContextAsync();
        var user = await db.Users.FirstOrDefaultAsync(item => item.Id == userId);
        if (user is null || user.IsBlocked)
            return new PasswordChangeOutcome(false, "Sesja jest nieprawidłowa. Zaloguj się ponownie.");

        if (!hasher.Verify(user.PasswordHash, current))
            return new PasswordChangeOutcome(false, "Obecne hasło jest niepoprawne.");

        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(item => item.Id == 1)
            ?? SecuritySettings.CreateDefault();
        var policyErrors = PasswordPolicy.Evaluate(next, user.Login, settings.RejectSequences);
        if (policyErrors.Count > 0)
            return new PasswordChangeOutcome(false, string.Join(" ", policyErrors));

        if (hasher.Verify(user.PasswordHash, next))
            return new PasswordChangeOutcome(false, "Nowe hasło musi różnić się od haseł użytych wcześniej.");

        var history = (await db.PasswordHistory
            .Where(entry => entry.UserId == user.Id)
            .ToListAsync())
            .OrderByDescending(entry => entry.CreatedAt)
            .Take(HistoryLimit)
            .ToList();

        if (history.Any(entry => hasher.Verify(entry.PasswordHash, next)))
            return new PasswordChangeOutcome(false, "Nowe hasło musi różnić się od haseł użytych wcześniej.");

        var now = DateTimeOffset.UtcNow;
        db.PasswordHistory.Add(new PasswordHistoryEntry
        {
            UserId = user.Id,
            PasswordHash = user.PasswordHash,
            CreatedAt = now,
        });
        user.PasswordHash = hasher.Hash(next);
        user.MustChangePassword = false;
        user.IsOneTimePassword = false;
        user.OneTimePasswordExpiresAt = null;
        user.PasswordChangedAt = now;
        await db.SaveChangesAsync();

        var stale = (await db.PasswordHistory
            .Where(entry => entry.UserId == user.Id)
            .ToListAsync())
            .OrderByDescending(entry => entry.CreatedAt)
            .Skip(HistoryLimit)
            .ToList();
        if (stale.Count > 0)
        {
            db.PasswordHistory.RemoveRange(stale);
            await db.SaveChangesAsync();
        }

        return new PasswordChangeOutcome(true, null);
    }
}
