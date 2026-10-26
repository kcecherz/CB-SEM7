namespace Klucznik.Security;

public static class PasswordPolicy
{
    public const int MinimumLength = 15;
    public const int MaximumLength = 128;

    public static IReadOnlyList<string> Evaluate(string? password, string? login, bool rejectSequences)
    {
        var value = password ?? "";
        var errors = new List<string>();

        if (value.Length < MinimumLength)
            errors.Add($"Hasło musi mieć co najmniej {MinimumLength} znaków.");

        if (value.Length > MaximumLength)
            errors.Add($"Hasło może mieć co najwyżej {MaximumLength} znaków.");

        if (BannedPasswords.Contains(value))
            errors.Add("Hasło znajduje się na liście haseł zakazanych.");

        if (!string.IsNullOrEmpty(login) && string.Equals(value, login.Trim(), StringComparison.OrdinalIgnoreCase))
            errors.Add("Hasło nie może być takie samo jak login.");

        if (rejectSequences && SequenceRules.ContainsForbiddenSequence(value))
        {
            errors.Add(
                "Hasło nie może zawierać sekwencji klawiaturowych ani ciągów rosnących lub malejących o długości co najmniej 4 (np. werty, asdf, 1234, abcd).");
        }

        return errors;
    }
}
