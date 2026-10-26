namespace Klucznik.Security;

public static class SequenceRules
{
    public const int RunLength = 4;

    private static readonly string[] Rows =
    [
        "1234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
    ];

    public static bool ContainsForbiddenSequence(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return false;

        var value = password.ToLowerInvariant();
        foreach (var row in Rows)
        {
            if (ContainsRun(value, row))
                return true;
        }

        return false;
    }

    private static bool ContainsRun(string password, string row)
    {
        if (row.Length < RunLength)
            return false;

        for (var start = 0; start <= row.Length - RunLength; start++)
        {
            var window = row.Substring(start, RunLength);
            if (password.Contains(window, StringComparison.Ordinal))
                return true;

            var descending = new string(window.Reverse().ToArray());
            if (password.Contains(descending, StringComparison.Ordinal))
                return true;
        }

        return false;
    }
}
