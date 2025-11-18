using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using SafeVault.Models;

namespace SafeVault.Data;

public partial class SafeVaultDbContext : IdentityDbContext<User, IdentityRole<int>, int>
{

    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(e => e.Id).HasColumnName("UserId")
                .ValueGeneratedOnAdd();

            entity.Property(e => e.Email).HasMaxLength(256).IsUnicode(false);

            entity.Property(e => e.UserName).HasMaxLength(256).IsUnicode(false);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
