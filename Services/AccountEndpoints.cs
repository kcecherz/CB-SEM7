using Klucznik.Security;
using Microsoft.AspNetCore.Antiforgery;

namespace Klucznik.Services;

public static class AccountEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/login", Login).AllowAnonymous().WithMetadata(new RequireAntiforgeryTokenAttribute());
        app.MapPost("/account/zmien-haslo", ChangePassword).RequireAuthorization().WithMetadata(new RequireAntiforgeryTokenAttribute());
        app.MapPost("/account/wyloguj", Logout).RequireAuthorization().WithMetadata(new RequireAntiforgeryTokenAttribute());
        app.MapGet("/account/wygasnij", Expire).AllowAnonymous();
    }

    private static async Task<IResult> Login(
        HttpContext http,
        [Microsoft.AspNetCore.Mvc.FromForm] string? login,
        [Microsoft.AspNetCore.Mvc.FromForm] string? password,
        [Microsoft.AspNetCore.Mvc.FromForm] string? powrot,
        AuthService auth)
    {
        var outcome = await auth.SignInAsync(http, login, password);
        if (!outcome.Succeeded)
        {
            var safeLogin = (login ?? "").Trim();
            if (safeLogin.Length > LoginRules.MaximumLength)
                safeLogin = "";

            var target = "/logowanie?blad=1"
                + "&login=" + Uri.EscapeDataString(safeLogin)
                + "&powrot=" + Uri.EscapeDataString(LocalRedirect.Normalize(powrot));
            return Results.Redirect(target);
        }

        var destination = outcome.MustChangePassword
            ? "/konto/haslo"
            : LocalRedirect.Normalize(powrot);
        return Results.Redirect(destination);
    }

    private static async Task<IResult> ChangePassword(
        HttpContext http,
        [Microsoft.AspNetCore.Mvc.FromForm] string? currentPassword,
        [Microsoft.AspNetCore.Mvc.FromForm] string? newPassword,
        [Microsoft.AspNetCore.Mvc.FromForm] string? confirmPassword,
        PasswordChangeService passwords)
    {
        var outcome = await passwords.ChangeAsync(http.User, currentPassword, newPassword, confirmPassword);
        if (!outcome.Succeeded)
        {
            var message = outcome.Error ?? "Nie udało się zmienić hasła.";
            return Results.Redirect("/konto/haslo?blad=" + Uri.EscapeDataString(message));
        }

        return Results.Redirect("/");
    }

    private static async Task<IResult> Logout(HttpContext http, SessionGate gate)
    {
        await gate.RevokeAsync(http.User, http);
        return Results.Redirect("/logowanie?powod=wylogowano");
    }

    private static IResult Expire(HttpContext http)
    {
        if (http.User.Identity?.IsAuthenticated == true)
            return Results.Redirect("/");

        return Results.Redirect("/logowanie?powod=zakonczona");
    }
}
