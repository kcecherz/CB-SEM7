using System.Security.Claims;
using Klucznik.Data;
using Klucznik.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public enum SessionVerdict
{
    Anonymous,
    Active,
    MustChangePassword,
    Idle,
    Ended,
}

public readonly record struct SessionSnapshot(
    SessionVerdict Verdict,
    DateTimeOffset LastActivityAt,
    int InactivityMinutes)
{
    public static SessionSnapshot Anonymous { get; } = new(SessionVerdict.Anonymous, default, SessionRules.DefaultMinutes);

    public TimeSpan? Remaining(DateTimeOffset now)
    {
        if (Verdict is not (SessionVerdict.Active or SessionVerdict.MustChangePassword))
            return null;

        var left = TimeSpan.FromMinutes(SessionRules.ClampMinutes(InactivityMinutes)) - (now - LastActivityAt);
        return left < TimeSpan.Zero ? TimeSpan.Zero : left;
    }
}

public sealed class SessionGate(IDbContextFactory<AppDbContext> factory)
{
    public async Task<SessionSnapshot> EvaluateAsync(ClaimsPrincipal principal, bool touch, DateTimeOffset now)
    {
        if (principal.Identity?.IsAuthenticated != true)
            return SessionSnapshot.Anonymous;

        if (!TryRead(principal, out var sessionId, out var userId))
            return Ended();

        await using var db = await factory.CreateDbContextAsync();
        var session = await db.Sessions.FirstOrDefaultAsync(item => item.Id == sessionId);
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(item => item.Id == userId);
        var settings = await LoadSettingsAsync(db);

        if (session is null || user is null || session.UserId != user.Id || user.IsBlocked)
            return Ended();

        if (SessionRules.IsIdle(session.LastActivityAt, now, settings.SessionInactivityMinutes))
            return new SessionSnapshot(SessionVerdict.Idle, session.LastActivityAt, settings.SessionInactivityMinutes);

        if (touch)
        {
            session.LastActivityAt = now;
            await db.SaveChangesAsync();
        }

        var mustChange = user.MustChangePassword
            || user.IsOneTimePassword
            || PasswordRules.IsExpired(user.PasswordChangedAt, settings.PasswordValidityDays, now);

        var verdict = mustChange ? SessionVerdict.MustChangePassword : SessionVerdict.Active;
        var activity = touch ? now : session.LastActivityAt;
        return new SessionSnapshot(verdict, activity, settings.SessionInactivityMinutes);
    }

    public async Task RevokeAsync(ClaimsPrincipal principal, HttpContext http)
    {
        if (TryRead(principal, out var sessionId, out _))
        {
            await using var db = await factory.CreateDbContextAsync();
            await db.Sessions.Where(session => session.Id == sessionId).ExecuteDeleteAsync();
        }

        await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    private static bool TryRead(ClaimsPrincipal principal, out Guid sessionId, out int userId)
    {
        sessionId = default;
        userId = default;
        var sid = principal.FindFirstValue("sid");
        var uid = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(sid, out sessionId) && int.TryParse(uid, out userId);
    }

    private static SessionSnapshot Ended() => new(SessionVerdict.Ended, default, SessionRules.DefaultMinutes);

    private static async Task<SecuritySettings> LoadSettingsAsync(AppDbContext db)
    {
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(item => item.Id == 1);
        return settings ?? SecuritySettings.CreateDefault();
    }
}
