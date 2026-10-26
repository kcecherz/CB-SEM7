using System.Security.Claims;
using Klucznik.Data;
using Klucznik.Security;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public sealed class SettingsService(IDbContextFactory<AppDbContext> factory)
{
    public async Task<SecuritySettings> GetAsync()
    {
        await using var db = await factory.CreateDbContextAsync();
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(item => item.Id == 1);
        return settings ?? SecuritySettings.CreateDefault();
    }

    public async Task<string?> UpdateAsync(
        ClaimsPrincipal actor,
        bool rejectSequences,
        int passwordValidityDays,
        int sessionInactivityMinutes)
    {
        await using var db = await factory.CreateDbContextAsync();
        if (!int.TryParse(actor.FindFirstValue(ClaimTypes.NameIdentifier), out var actorId))
            return "Brak uprawnień.";

        var account = await db.Users.AsNoTracking().FirstOrDefaultAsync(user => user.Id == actorId && !user.IsBlocked);
        if (account is null || !AccessCatalog.Has(account.Role, Permission.ManageSecurityPolicy))
            return "Brak uprawnień.";

        if (passwordValidityDays is < 0 or > 365)
            return "Ważność hasła podaj w dniach, od 0 do 365. Zero oznacza brak wygaśnięcia.";

        if (sessionInactivityMinutes is < SessionRules.MinimumMinutes or > SessionRules.MaximumMinutes)
            return $"Czas bezczynności musi wynosić od {SessionRules.MinimumMinutes} do {SessionRules.MaximumMinutes} minut.";

        var settings = await db.Settings.FirstOrDefaultAsync(item => item.Id == 1);
        if (settings is null)
        {
            settings = SecuritySettings.CreateDefault();
            db.Settings.Add(settings);
        }

        settings.RejectSequences = rejectSequences;
        settings.PasswordValidityDays = passwordValidityDays;
        settings.SessionInactivityMinutes = sessionInactivityMinutes;
        await db.SaveChangesAsync();
        return null;
    }
}
