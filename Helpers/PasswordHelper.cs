using BCrypt.Net;

namespace SafeVault.Helpers;

/// <summary>
/// Proporciona métodos para hashear y verificar contraseñas de forma segura usando BCrypt.
/// (Mitiga A07:2021 - Fallas de Identificación y Autenticación)
/// </summary>
public static class PasswordHelper
{
    // Se recomienda usar la versión "enhanced" para mayor seguridad.
    // El 'salt' se genera automáticamente dentro de HashPassword.
    
    /// <summary>
    /// Hashea una contraseña usando BCrypt.
    /// </summary>
    /// <param name="password">La contraseña en texto plano.</param>
    /// <returns>El hash de la contraseña (incluyendo el salt).</returns>
    public static string HashPassword(string password)
    {
        // El 'work factor' (costo) por defecto de BCrypt.Net-Core es 13, que es robusto.
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 13, enhancedEntropy: true);
    }

    /// <summary>
    /// Verifica una contraseña de texto plano contra un hash existente.
    /// </summary>
    /// <param name="password">La contraseña de texto plano ingresada por el usuario.</param>
    /// <param name="hash">El hash almacenado en la base de datos.</param>
    /// <returns>True si la contraseña coincide con el hash, False en caso contrario.</returns>
    public static bool VerifyPassword(string password, string hash)
    {
        // BCrypt maneja automáticamente la extracción del salt del hash para la verificación.
        return BCrypt.Net.BCrypt.Verify(password, hash, enhancedEntropy: true);
    }
}