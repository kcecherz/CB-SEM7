namespace Klucznik.Data;

public sealed class UserAccount
{
    public int Id { get; set; }
    public string Login { get; set; } = "";
    public string LoginNormalized { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "";
    public bool IsBlocked { get; set; }
    public bool MustChangePassword { get; set; }
    public bool IsOneTimePassword { get; set; }
    public DateTimeOffset? OneTimePasswordExpiresAt { get; set; }
    public DateTimeOffset PasswordChangedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public bool IsPermanentAdmin { get; set; }
    public List<PasswordHistoryEntry> PasswordHistory { get; set; } = [];
    public List<UserSession> Sessions { get; set; } = [];
}

public sealed class PasswordHistoryEntry
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public UserAccount? User { get; set; }
    public string PasswordHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class UserSession
{
    public Guid Id { get; set; }
    public int UserId { get; set; }
    public UserAccount? User { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastActivityAt { get; set; }
}

public sealed class SecuritySettings
{
    public int Id { get; set; }
    public bool RejectSequences { get; set; }
    public int PasswordValidityDays { get; set; }
    public int SessionInactivityMinutes { get; set; }

    public static SecuritySettings CreateDefault() => new()
    {
        Id = 1,
        RejectSequences = false,
        PasswordValidityDays = 0,
        SessionInactivityMinutes = Security.SessionRules.DefaultMinutes,
    };
}
