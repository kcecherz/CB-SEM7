using System.Security.Claims;
using Klucznik.Data;
using Klucznik.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public sealed record SignInOutcome(bool Succeeded, bool MustChangePassword);

public sealed class AuthService(IDbContextFactory<AppDbContext> factory, PasswordHasher hasher, ILogger<AuthService> logger)
{
    public const string FailureMessage = "Login lub hasło niepoprawne";

    public async Task<SignInOutcome> SignInAsync(HttpContext http, string? login, string? password)
    {
        var rawLogin = (login ?? "").Trim();
        var rawPassword = password ?? "";
        var now = DateTimeOffset.UtcNow;

        if (rawLogin.Length is < 1 or > LoginRules.MaximumLength || rawPassword.Length > PasswordPolicy.MaximumLength)
        {
            hasher.Verify(hasher.DummyHash, "odrzut");
            logger.LogInformation("Odrzucono próbę logowania.");
            return new SignInOutcome(false, false);
        }

        await using var db = await factory.CreateDbContextAsync();
        var normalized = LoginRules.Normalize(rawLogin);
        var user = await db.Users.FirstOrDefaultAsync(item => item.LoginNormalized == normalized);
        var hash = user?.PasswordHash ?? hasher.DummyHash;
        var passwordMatches = hasher.Verify(hash, rawPassword);

        var oneTimeExpired = user is { IsOneTimePassword: true, OneTimePasswordExpiresAt: { } until } && until < now;
        if (user is null || !passwordMatches || user.IsBlocked || oneTimeExpired)
        {
            logger.LogInformation("Odrzucono próbę logowania.");
            return new SignInOutcome(false, false);
        }

        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(item => item.Id == 1)
            ?? SecuritySettings.CreateDefault();

        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            CreatedAt = now,
            LastActivityAt = now,
        };
        db.Sessions.Add(session);
        await db.SaveChangesAsync();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Login),
            new(ClaimTypes.Role, user.Role),
            new("sid", session.Id.ToString()),
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await http.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties
            {
                IsPersistent = false,
                AllowRefresh = false,
                IssuedUtc = now.UtcDateTime,
            });

        var mustChange = user.MustChangePassword
            || user.IsOneTimePassword
            || PasswordRules.IsExpired(user.PasswordChangedAt, settings.PasswordValidityDays, now);

        logger.LogInformation("Zalogowano użytkownika {Login}.", user.Login);
        return new SignInOutcome(true, mustChange);
    }
}
