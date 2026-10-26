namespace Klucznik.Security;

public static class LocalRedirect
{
    public static string Normalize(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
            return "/";

        var value = returnUrl.Trim();
        if (!value.StartsWith('/'))
            return "/";

        if (value.StartsWith("//", StringComparison.Ordinal) || value.StartsWith("/\\", StringComparison.Ordinal))
            return "/";

        if (value.Contains("://", StringComparison.Ordinal) || value.Contains('\\'))
            return "/";

        if (value.StartsWith("/logowanie", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/account/", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/wyloguj", StringComparison.OrdinalIgnoreCase))
            return "/";

        return value;
    }
}
