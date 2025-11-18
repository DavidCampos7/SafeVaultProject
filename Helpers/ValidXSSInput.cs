using System;
using System.Text.RegularExpressions;
namespace SafeVault.Helpers;

public class ValidXSSInput
{
    /// <summary>
    /// Valida que la entrada no contenga scripts o etiquetas HTML peligrosas
    /// </summary>
    /// <param name="input">Texto a validar</param>
    /// <returns>true si es seguro, false en caso contrario</returns>
    public static bool IsSafeInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        // Patrón para detectar etiquetas HTML y scripts
        string pattern = @"<script.*?>.*?</script>|<.*?>";
        return !Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase);
    }
}