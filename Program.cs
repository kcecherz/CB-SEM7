using System.Globalization;
using Klucznik.Components;
using Klucznik.Data;
using Klucznik.Security;
using Klucznik.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Localization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var dataDir = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(dataDir);
var connectionString = new SqliteConnectionStringBuilder
{
    DataSource = Path.Combine(dataDir, "klucznik.db"),
    Mode = SqliteOpenMode.ReadWriteCreate,
    Cache = SqliteCacheMode.Shared,
    DefaultTimeout = 15,
}.ToString();

builder.Services.AddSingleton<SqlitePragmaInterceptor>();
builder.Services.AddDbContextFactory<AppDbContext>((services, options) =>
{
    options.UseSqlite(connectionString);
    options.AddInterceptors(services.GetRequiredService<SqlitePragmaInterceptor>());
});

builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<PasswordChangeService>();
builder.Services.AddScoped<UserAdminService>();
builder.Services.AddScoped<SettingsService>();
builder.Services.AddScoped<SessionGate>();
builder.Services.AddScoped<CurrentAccount>();
builder.Services.AddScoped<IClaimsTransformation, RoleRefreshTransformation>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "klucznik.sesja";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.SlidingExpiration = false;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.LoginPath = "/logowanie";
        options.AccessDeniedPath = "/brak-dostepu";
        options.ReturnUrlParameter = "powrot";
    });

builder.Services.AddAuthorization(options => AccessCatalog.RegisterPolicies(options));
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>();
    await using var db = await factory.CreateDbContextAsync();
    await db.Database.EnsureCreatedAsync();
    var connection = db.Database.GetDbConnection();
    if (connection.State != System.Data.ConnectionState.Open)
        await connection.OpenAsync();
    await using var pragma = connection.CreateCommand();
    pragma.CommandText = "PRAGMA journal_mode=WAL;";
    await pragma.ExecuteScalarAsync();

    var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();
    await DbSeeder.SeedAsync(db, hasher, dataDir);
}

var culture = CultureInfo.GetCultureInfo("pl-PL");
CultureInfo.DefaultThreadCurrentCulture = culture;
CultureInfo.DefaultThreadCurrentUICulture = culture;

if (app.Environment.IsDevelopment())
    app.UseDeveloperExceptionPage();
else
    app.UseExceptionHandler("/Error", createScopeForErrors: true);

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseRequestLocalization(new RequestLocalizationOptions
{
    DefaultRequestCulture = new RequestCulture(culture),
    SupportedCultures = [culture],
    SupportedUICultures = [culture],
});
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<SessionGuardMiddleware>();
app.UseAntiforgery();

AccountEndpoints.Map(app);
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();
