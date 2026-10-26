namespace Klucznik.Security;

public static class BannedPasswords
{
    private static readonly HashSet<string> Entries = new(StringComparer.OrdinalIgnoreCase)
    {
        "passwordpassword",
        "password1234567",
        "qwertyuiopasdfg",
        "qwertyuiopasdfgh",
        "123456789012345",
        "1234567890123456",
        "111111111111111",
        "000000000000000",
        "aaaaaaaaaaaaaaa",
        "haslohaslohaslo",
        "haslohaslohaslo1",
        "administrator123",
        "administrator1!",
        "zaq12wsxcde34rf",
        "1q2w3e4r5t6y7u8",
        "qazwsxedcrfvtgb",
        "polskapolskapolska",
        "klucznikklucznik",
    };

    public static bool Contains(string? password) =>
        !string.IsNullOrEmpty(password) && Entries.Contains(password);
}
