using System;
using System.Text.RegularExpressions;
using SafeVault.Models;
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Helpers;

public class UserLogin
{
    /// <summary>
    /// Valida las credenciales de login del usuario
    /// </summary>
    /// <param name="email">Email del usuario</param>
    /// <param name="password">Contraseña del usuario</param>
    /// <returns>true si las credenciales son válidas, false en caso contrario</returns>
    public static bool ValidateLoginInput(string email, string password)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return false;

        string emailPattern = @"^[^\s@]+@[^\s@]+\.[^\s@]+$";
        if (!Regex.IsMatch(email, emailPattern))
            return false;

        if (password.Length < 8)
            return false;

        return true;
    }

    /// <summary>
    /// Autentica un usuario usando ASP.NET Identity
    /// </summary>
    /// <param name="userManager">UserManager para acceder a usuarios</param>
    /// <param name="email">Email del usuario</param>
    /// <param name="password">Contraseña del usuario</param>
    /// <returns>Usuario si la autenticación es exitosa, null en caso contrario</returns>
    public static async Task<User?> AuthenticateUserAsync(UserManager<User> userManager, string email, string password)
    {
        if (!ValidateLoginInput(email, password))
            return null;

        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
            return null;

        bool isValid = await userManager.CheckPasswordAsync(user, password);
        return isValid ? user : null;
    }

    /// <summary>
    /// Valida entrada y retorna mensaje descriptivo
    /// </summary>
    public static (bool isValid, string message) ValidateLoginInputWithMessage(string email, string password)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return (false, "Email y contraseña son requeridos.");

        string emailPattern = @"^[^\s@]+@[^\s@]+\.[^\s@]+$";
        if (!Regex.IsMatch(email, emailPattern))
            return (false, "El formato del email no es válido.");

        if (password.Length < 8)
            return (false, "La contraseña debe tener al menos 8 caracteres.");

        return (true, "Credenciales válidas.");
    }
}