using Microsoft.EntityFrameworkCore;

namespace Klucznik.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<UserAccount> Users => Set<UserAccount>();
    public DbSet<PasswordHistoryEntry> PasswordHistory => Set<PasswordHistoryEntry>();
    public DbSet<UserSession> Sessions => Set<UserSession>();
    public DbSet<SecuritySettings> Settings => Set<SecuritySettings>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserAccount>(entity =>
        {
            entity.HasIndex(user => user.LoginNormalized).IsUnique();
            entity.Property(user => user.Login).HasMaxLength(32);
            entity.Property(user => user.LoginNormalized).HasMaxLength(32);
            entity.Property(user => user.Role).HasMaxLength(32);
            entity.Property(user => user.PasswordHash).HasMaxLength(512);
        });

        modelBuilder.Entity<PasswordHistoryEntry>(entity =>
        {
            entity.Property(entry => entry.PasswordHash).HasMaxLength(512);
            entity.HasOne(entry => entry.User)
                .WithMany(user => user.PasswordHistory)
                .HasForeignKey(entry => entry.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserSession>(entity =>
        {
            entity.HasOne(session => session.User)
                .WithMany(user => user.Sessions)
                .HasForeignKey(session => session.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(session => session.UserId);
        });

        modelBuilder.Entity<SecuritySettings>(entity =>
        {
            entity.Property(settings => settings.Id).ValueGeneratedNever();
        });
    }
}
