namespace Klucznik.Security;

public static class SessionRules
{
    public const int MinimumMinutes = 1;
    public const int MaximumMinutes = 480;
    public const int DefaultMinutes = 15;

    public static int ClampMinutes(int minutes) => Math.Clamp(minutes, MinimumMinutes, MaximumMinutes);

    public static bool IsIdle(DateTimeOffset lastActivityAt, DateTimeOffset now, int inactivityMinutes)
    {
        var limit = TimeSpan.FromMinutes(ClampMinutes(inactivityMinutes));
        return now - lastActivityAt >= limit;
    }
}
