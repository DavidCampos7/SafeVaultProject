using System.ComponentModel.DataAnnotations;

namespace SafeVault.ViewModels;

public class RegisterViewModel
{
    [Required]
    [Display(Name = "Nombre de usuario")]
    public string UserName { get; set; } = null!;

    [Required]
    [EmailAddress]
    [Display(Name = "Correo electrónico")]
    public string Email { get; set; } = null!;

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Contraseña")]
    public string Password { get; set; } = null!;
}