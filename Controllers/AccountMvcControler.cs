using Microsoft.AspNetCore.Mvc;
using SafeVault.ViewModels;
using SafeVault.Models;
using SafeVault.Helpers;
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Controllers;

public class AccountMvcController : Controller
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;

    public AccountMvcController(UserManager<User> userManager, SignInManager<User> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        if (!ValidXSSInput.IsSafeInput(model.UserName))
        {
            ModelState.AddModelError("UserName", "El nombre de usuario contiene caracteres no permitidos.");
            return View(model);
        }

        var (usernameValid, usernameMsg) = InputValidation.ValidateUserInputWithMessage(model.UserName);
        if (!usernameValid)
        {
            ModelState.AddModelError("UserName", usernameMsg);
            return View(model);
        }

        try
        {
            var addr = new System.Net.Mail.MailAddress(model.Email);
            if (addr.Address != model.Email)
                throw new Exception();
        }
        catch
        {
            ModelState.AddModelError("Email", "El email no es válido.");
            return View(model);
        }

        var (passwordValid, passwordMsg) = InputValidation.ValidatePasswordComplexityWithMessage(model.Password);
        if (!passwordValid)
        {
            ModelState.AddModelError("Password", passwordMsg);
            return View(model);
        }

        var user = new User
        {
            UserName = model.UserName,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            TempData["StatusMessage"] = "Registro exitoso. ¡Bienvenido!";
            return RedirectToAction("Login");
        }

        foreach (var error in result.Errors)
            ModelState.AddModelError(string.Empty, error.Description);

        return View(model);
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var (isValid, message) = UserLogin.ValidateLoginInputWithMessage(model.Email, model.Password);
        if (!isValid)
        {
            ModelState.AddModelError(string.Empty, message);
            return View(model);
        }

        var user = await UserLogin.AuthenticateUserAsync(_userManager, model.Email, model.Password);
        if (user != null)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction("Index", "Home");
        }

        ModelState.AddModelError(string.Empty, "Credenciales inválidas.");
        return View(model);
    }
}