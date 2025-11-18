using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;
using Microsoft.AspNetCore.Identity; // Necesario
using Microsoft.Extensions.Configuration; // Necesario
using Microsoft.Extensions.Logging; // Necesario

namespace SafeVault.Service;

public class TokenService : ITokenService
{
    private readonly string _key;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _expireMinutes;
    private readonly ILogger<TokenService> _logger;
    private readonly UserManager<User> _userManager; // Nuevo

    public TokenService(
        IConfiguration configuration, 
        ILogger<TokenService> logger,
        UserManager<User> userManager) // Inyección del UserManager
    {
        _key = configuration["jwt:Key"] ?? throw new ArgumentNullException("JWT Key is not configured.");
        _issuer = configuration["jwt:Issuer"] ?? throw new ArgumentNullException("JWT Issuer is not configured.");
        _audience = configuration["jwt:Audience"] ?? throw new ArgumentNullException("JWT Audience is not configured.");
        _expireMinutes = int.Parse(configuration["jwt:ExpireMinutes"] ?? "30");
        _logger = logger;
        _userManager = userManager; // Asignación del UserManager
    }

    /// <summary>
    /// Genera un token JWT seguro para el usuario, incluyendo sus roles
    /// </summary>
    /// <param name="user">Usuario para el cual generar el token</param>
    /// <returns>Token JWT codificado</returns>
    public async Task<string> GenerateToken(User user) // Cambiar a async Task<string>
    {
        try
        {
            // ... (Validaciones de usuario)

            // Obtener roles del usuario (REQUIERE ASYNC)
            var userRoles = await _userManager.GetRolesAsync(user);

            // Crear lista mutable de claims
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };
            
            // ⭐️ AGREGAR CLAIMS DE ROL
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            // ⭐️ Fin de la adición de claims de rol

            // Crear clave de seguridad
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Crear token JWT
            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims, // Usar la lista con los roles
                expires: DateTime.UtcNow.AddMinutes(_expireMinutes),
                signingCredentials: creds);

            var tokenHandler = new JwtSecurityTokenHandler();
            string encodedToken = tokenHandler.WriteToken(token);

            _logger.LogInformation($"Token JWT generado para usuario: {user.UserName} con roles: [{string.Join(", ", userRoles)}]");
            return encodedToken;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error al generar token JWT: {ex.Message}");
            throw;
        }
    }
}

public interface ITokenService
{
    // Cambiar a Task<string>
    Task<string> GenerateToken(User user);
}