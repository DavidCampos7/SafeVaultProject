using System;
using System.Text.RegularExpressions;

namespace SafeVault.Helpers;

public class InputValidation
{
    /// <summary>
    /// Valida que la entrada contenga solo letras, dígitos y caracteres especiales (@, #, $)
    /// </summary>
    /// <param name="input">Texto a validar</param>
    /// <returns>true si es válido, false en caso contrario</returns>
    public static bool ValidateUserInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        // Patrón que permite solo letras, dígitos y caracteres especiales (@, #, $)
        // Este patrón es restrictivo y bueno para Usernames.
        string pattern = @"^[a-zA-Z0-9@#$]+$";
        return Regex.IsMatch(input, pattern);
    }

    /// <summary>
    /// Valida entrada y retorna mensaje descriptivo
    /// </summary>
    public static (bool isValid, string message) ValidateUserInputWithMessage(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return (false, "La entrada no puede estar vacía.");
        }
        
        // Se recomienda también validar la longitud mínima para Username (e.g., 3 caracteres)
        if (input.Length < 3 || input.Length > 20)
        {
             return (false, "La longitud debe estar entre 3 y 20 caracteres.");
        }

        if (!ValidateUserInput(input))
        {
            return (false, "La entrada contiene caracteres no permitidos. Solo se permiten letras, dígitos y @, #, $");
        }

        return (true, "Entrada válida.");
    }
    
// ----------------------------------------------------------------------------------

    /// <summary>
    /// Valida la complejidad de la contraseña según políticas de seguridad.
    /// Requisitos: Mínimo 12 caracteres, mayúscula, minúscula, dígito y símbolo.
    /// </summary>
    /// <param name="password">La contraseña a validar.</param>
    /// <returns>Tupla con el estado de validez y un mensaje descriptivo.</returns>
    public static (bool isValid, string message) ValidatePasswordComplexityWithMessage(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return (false, "La contraseña no puede estar vacía.");
        }

        // 1. Longitud Mínima (Recomendación actual: 12 caracteres)
        const int MIN_LENGTH = 12;
        if (password.Length < MIN_LENGTH)
        {
            return (false, $"La contraseña debe tener al menos {MIN_LENGTH} caracteres.");
        }

        // 2. Comprobación de Complejidad con Expresiones Regulares
        
        // Requiere al menos un dígito
        if (!Regex.IsMatch(password, @"\d"))
        {
            return (false, "La contraseña debe contener al menos un dígito (0-9).");
        }

        // Requiere al menos una letra mayúscula
        if (!Regex.IsMatch(password, @"[A-Z]"))
        {
            return (false, "La contraseña debe contener al menos una letra mayúscula.");
        }

        // Requiere al menos una letra minúscula
        if (!Regex.IsMatch(password, @"[a-z]"))
        {
            return (false, "La contraseña debe contener al menos una letra minúscula.");
        }

        // Requiere al menos un carácter especial (se permite un amplio rango para ser más flexible)
        // Se usa [^a-zA-Z0-9\s] para buscar cualquier cosa que NO sea letra, dígito o espacio en blanco.
        if (!Regex.IsMatch(password, @"[^a-zA-Z0-9\s]"))
        {
            return (false, "La contraseña debe contener al menos un carácter especial (símbolo).");
        }
        
        // La contraseña cumple con todos los requisitos
        return (true, "Contraseña válida.");
    }
    
// ----------------------------------------------------------------------------------

    /// <summary>
    /// Valida de forma genérica las entradas de email y password para el Login, 
    /// evitando mensajes descriptivos que ayuden a un atacante.
    /// </summary>
    public static (bool isValid, string message) ValidateLoginInputWithMessage(string email, string password)
    {
        // Validación básica de no nulidad
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            // Mensaje genérico para no dar pistas
            return (false, "Datos de inicio de sesión incompletos."); 
        }

        // Se puede añadir una validación de formato básico para el email aquí si se desea.

        // Si ambas entradas tienen contenido, se permite que el controlador intente la autenticación.
        return (true, string.Empty);
    }
}