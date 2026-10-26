using System.Security.Claims;
using Klucznik.Data;
using Klucznik.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public sealed class RoleRefreshTransformation(IDbContextFactory<AppDbContext> factory) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true || principal.HasClaim("role_fresh", "1"))
            return principal;

        if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            return principal;

        await using var db = await factory.CreateDbContextAsync();
        var role = await db.Users
            .AsNoTracking()
            .Where(user => user.Id == userId)
            .Select(user => user.Role)
            .FirstOrDefaultAsync();

        if (string.IsNullOrEmpty(role))
            return principal;

        var identity = principal.Identity as ClaimsIdentity;
        if (identity is null)
            return principal;

        var clone = new ClaimsIdentity(identity);
        foreach (var claim in clone.FindAll(ClaimTypes.Role).ToList())
            clone.RemoveClaim(claim);

        clone.AddClaim(new Claim(ClaimTypes.Role, role));
        clone.AddClaim(new Claim("role_fresh", "1"));
        return new ClaimsPrincipal(clone);
    }
}
