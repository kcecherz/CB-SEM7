using Klucznik.Security;

namespace Klucznik.Services;

public sealed class SessionGuardMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, SessionGate gate)
    {
        if (IsAsset(context.Request.Path))
        {
            await next(context);
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var path = context.Request.Path;
        var touch = !IsLogin(path) && !IsExpire(path);
        var snapshot = await gate.EvaluateAsync(context.User, touch, now);

        switch (snapshot.Verdict)
        {
            case SessionVerdict.Anonymous:
                await next(context);
                return;
            case SessionVerdict.Idle:
            case SessionVerdict.Ended:
                await gate.RevokeAsync(context.User, context);
                if (IsLogin(path))
                {
                    await next(context);
                    return;
                }

                var reason = snapshot.Verdict == SessionVerdict.Idle ? "bezczynnosc" : "zakonczona";
                context.Response.Redirect($"/logowanie?powod={reason}");
                return;
            case SessionVerdict.Active:
            case SessionVerdict.MustChangePassword:
                if (IsLogin(path))
                {
                    var destination = snapshot.Verdict == SessionVerdict.MustChangePassword
                        ? "/konto/haslo"
                        : LocalRedirect.Normalize(context.Request.Query["powrot"]);
                    context.Response.Redirect(destination);
                    return;
                }

                if (snapshot.Verdict == SessionVerdict.MustChangePassword && !IsAllowedDuringPasswordChange(path))
                {
                    context.Response.Redirect("/konto/haslo");
                    return;
                }

                await next(context);
                return;
            default:
                await next(context);
                return;
        }
    }

    private static bool IsAsset(PathString path)
    {
        var value = path.Value ?? "";
        if (value.StartsWith("/_framework", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/_blazor", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/_content", StringComparison.OrdinalIgnoreCase))
            return true;

        var slash = value.LastIndexOf('/');
        var last = slash >= 0 ? value[(slash + 1)..] : value;
        return last.Contains('.');
    }

    private static bool IsLogin(PathString path) =>
        path.Equals("/logowanie", StringComparison.OrdinalIgnoreCase);

    private static bool IsExpire(PathString path) =>
        path.Equals("/account/wygasnij", StringComparison.OrdinalIgnoreCase);

    private static bool IsAllowedDuringPasswordChange(PathString path)
    {
        var value = path.Value ?? "";
        return value.Equals("/konto/haslo", StringComparison.OrdinalIgnoreCase)
            || value.Equals("/account/zmien-haslo", StringComparison.OrdinalIgnoreCase)
            || value.Equals("/wyloguj", StringComparison.OrdinalIgnoreCase)
            || value.Equals("/account/wyloguj", StringComparison.OrdinalIgnoreCase)
            || value.Equals("/account/wygasnij", StringComparison.OrdinalIgnoreCase);
    }
}
