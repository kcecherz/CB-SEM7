using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Klucznik.Security;

public enum Permission
{
    ManageUsers,
    ManageSecurityPolicy,
    ResetPasswords,
}

public sealed record PermissionInfo(Permission Permission, string Name, string Description);

public static class AccessCatalog
{
    public const string ManageUsers = nameof(Permission.ManageUsers);
    public const string ManageSecurityPolicy = nameof(Permission.ManageSecurityPolicy);
    public const string ResetPasswords = nameof(Permission.ResetPasswords);

    public const string Administrator = "Administrator";
    public const string Redaktor = "Redaktor";
    public const string Czytelnik = "Czytelnik";
    public const string PermanentLogin = "ADMIN";

    private static readonly HashSet<Permission> All =
    [
        Permission.ManageUsers,
        Permission.ManageSecurityPolicy,
        Permission.ResetPasswords,
    ];

    private static readonly HashSet<Permission> None = [];

    private static readonly Dictionary<string, HashSet<Permission>> ByRole = new(StringComparer.Ordinal)
    {
        [Administrator] = All,
        [Redaktor] = None,
        [Czytelnik] = None,
    };

    public static readonly IReadOnlyList<string> Roles = [Administrator, Redaktor, Czytelnik];

    public static readonly IReadOnlyList<PermissionInfo> Permissions =
    [
        new(Permission.ManageUsers, "Zarządzanie użytkownikami", "Lista, tworzenie, edycja, blokowanie i usuwanie kont."),
        new(Permission.ManageSecurityPolicy, "Zasady haseł i sesji", "Sekwencje klawiaturowe, ważność hasła i czas bezczynności."),
        new(Permission.ResetPasswords, "Hasła jednorazowe", "Nadawanie hasła przy tworzeniu konta i przy resecie."),
    ];

    public static bool IsRole(string? role) => role is not null && ByRole.ContainsKey(role);

    public static bool Has(string? role, Permission permission) =>
        role is not null && ByRole.TryGetValue(role, out var granted) && granted.Contains(permission);

    public static bool Has(ClaimsPrincipal principal, Permission permission) =>
        Has(principal.FindFirstValue(ClaimTypes.Role), permission);

    public static IReadOnlyList<PermissionInfo> ForRole(string? role) =>
        Permissions.Where(item => Has(role, item.Permission)).ToList();

    public static void RegisterPolicies(AuthorizationOptions options)
    {
        Add(options, ManageUsers, Permission.ManageUsers);
        Add(options, ManageSecurityPolicy, Permission.ManageSecurityPolicy);
        Add(options, ResetPasswords, Permission.ResetPasswords);
    }

    private static void Add(AuthorizationOptions options, string name, Permission permission)
    {
        options.AddPolicy(name, policy =>
            policy.RequireAuthenticatedUser()
                .RequireAssertion(context => Has(context.User, permission)));
    }
}
