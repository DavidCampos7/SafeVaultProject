using Microsoft.AspNetCore.Mvc;
using SafeVault.ViewModels;
using SafeVault.Models;
using SafeVault.Service;
using SafeVault.Helpers;
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly ITokenService _tokenService;

    public AccountController(UserManager<User> userManager, ITokenService tokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
    }

    // El registro es un POST en la API, devuelve el token
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        // 1. Validar el estado del modelo
        if (!ModelState.IsValid)
            return BadRequest(ModelState); // Retorna 400 Bad Request con errores

        // 2. Validaciones de seguridad (Mantenidas)
        if (!ValidXSSInput.IsSafeInput(model.UserName))
        {
            ModelState.AddModelError("UserName", "El nombre de usuario contiene caracteres no permitidos.");
            return BadRequest(ModelState);
        }

        var (usernameValid, usernameMsg) = InputValidation.ValidateUserInputWithMessage(model.UserName);
        if (!usernameValid)
        {
            ModelState.AddModelError("UserName", usernameMsg);
            return BadRequest(ModelState);
        }
        
        // La validación de email con try/catch es funcional, pero si usas DataAnnotations en el ViewModel,
        // esto podría simplificarse. Aquí se mantiene la lógica:
        try
        {
            var addr = new System.Net.Mail.MailAddress(model.Email);
            if (addr.Address != model.Email) throw new Exception();
        }
        catch
        {
            ModelState.AddModelError("Email", "El email no es válido.");
            return BadRequest(ModelState);
        }

        var (passwordValid, passwordMsg) = InputValidation.ValidatePasswordComplexityWithMessage(model.Password);
        if (!passwordValid)
        {
            ModelState.AddModelError("Password", passwordMsg);
            return BadRequest(ModelState);
        }

        // 3. Crear usuario
        var user = new User
        {
            UserName = model.UserName,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            // 🔑 Éxito: Generar JWT y devolverlo
            var token = _tokenService.GenerateToken(user);

            // 💡 Retorna 200 OK con el token
            return Ok(new { Message = "Registro exitoso.", Token = token });
        }

        // 4. Fallo: Retornar errores de Identity
        foreach (var error in result.Errors)
            ModelState.AddModelError(string.Empty, error.Description);

        return BadRequest(ModelState); // Retorna 400 Bad Request
    }

    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        // La validación con UserLogin.ValidateLoginInputWithMessage es mantenida si es necesaria.
        var (isValid, message) = UserLogin.ValidateLoginInputWithMessage(model.Email, model.Password);
        if (!isValid)
        {
            return Unauthorized(new { Message = message }); // Retorna 401 Unauthorized
        }

        // 1. Buscar el usuario
        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user == null)
        {
            // Retornar un mensaje genérico por seguridad
            return Unauthorized(new { Message = "Credenciales inválidas." });
        }
        
        // 2. Verificar la contraseña
        var passwordCheck = await _userManager.CheckPasswordAsync(user, model.Password);

        if (passwordCheck)
        {
            // 🔑 Éxito: Generar JWT y devolverlo
            var token = _tokenService.GenerateToken(user);
            
            // 💡 Retorna 200 OK con el token
            return Ok(new { Token = token });
        }

        // Fallo en la contraseña
        return Unauthorized(new { Message = "Credenciales inválidas." }); // Retorna 401 Unauthorized
    }
    
}