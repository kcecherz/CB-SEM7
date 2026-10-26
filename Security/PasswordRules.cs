namespace Klucznik.Security;

public static class PasswordRules
{
    public static bool IsExpired(DateTimeOffset passwordChangedAt, int validityDays, DateTimeOffset now)
    {
        if (validityDays <= 0)
            return false;

        return passwordChangedAt.AddDays(validityDays) <= now;
    }
}
