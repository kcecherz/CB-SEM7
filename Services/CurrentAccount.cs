using System.Security.Claims;
using Klucznik.Data;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Klucznik.Services;

public sealed class CurrentAccount(IDbContextFactory<AppDbContext> factory, AuthenticationStateProvider auth)
{
    public async Task<UserAccount?> FindAsync()
    {
        var state = await auth.GetAuthenticationStateAsync();
        if (!int.TryParse(state.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id))
            return null;

        await using var db = await factory.CreateDbContextAsync();
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(user => user.Id == id);
    }
}
