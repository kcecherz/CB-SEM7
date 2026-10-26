using System.Text.RegularExpressions;

namespace Klucznik.Security;

public static partial class LoginRules
{
    public const int MinimumLength = 3;
    public const int MaximumLength = 32;

    [GeneratedRegex(@"^[A-Za-z0-9ĄĆĘŁŃÓŚŹŻąćęłńóśźż][A-Za-z0-9ĄĆĘŁŃÓŚŹŻąćęłńóśźż._-]{2,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex LoginPattern();

    public static string Normalize(string login) => login.Trim().ToUpperInvariant();

    public static string? Validate(string? login)
    {
        if (string.IsNullOrWhiteSpace(login))
            return "Podaj login.";

        var value = login.Trim();
        if (value.Length < MinimumLength || value.Length > MaximumLength)
            return $"Login musi mieć od {MinimumLength} do {MaximumLength} znaków.";

        if (!LoginPattern().IsMatch(value))
            return "Login może zawierać litery, cyfry oraz znaki . _ - i musi zaczynać się od litery lub cyfry.";

        return null;
    }
}
