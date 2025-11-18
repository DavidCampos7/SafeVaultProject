using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// ----------------------
// 1. Crear roles al iniciar
// ----------------------
async Task CreateRolesAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<int>>>();

    string[] roles = { "Admin", "User", "Manager" };

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole<int>(role));
        }
    }
}

// ----------------------
// 2. Agregar servicios
// ----------------------
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("connectionDB"))
);

builder.Services.AddIdentity<User, IdentityRole<int>>()
    .AddEntityFrameworkStores<SafeVaultDbContext>()
    .AddDefaultTokenProviders();

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false; // Mejora la seguridad al ocultar la versión del servidor
    options.ListenAnyIP(5001, listenoptions => {listenoptions.UseHttps();}); // Escuchar en el puerto 5001 para HTTPS
    options.ListenAnyIP(5000); // Escuchar en el puerto 5000 para HTTP
});

// JWT
var jwtSettings = builder.Configuration.GetSection("jwt");

builder.Services.AddAuthentication("JwtBearer")
.AddJwtBearer("JwtBearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? "")
        ),

        // NECESARIO PARA RBAC
        RoleClaimType = ClaimTypes.Role
    };
});

builder.Services.AddAuthorization();

builder.Services.AddScoped<ITokenService, TokenService>();

var app = builder.Build();

// Crear roles automáticamente
await CreateRolesAsync(app);

// ----------------------
// 3. Pipeline
// ----------------------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
