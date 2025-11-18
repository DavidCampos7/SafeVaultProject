using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]  // Solo admins pueden manipular roles
    public class RolesController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole<int>> _roleManager;

        public RolesController(
            UserManager<User> userManager,
            RoleManager<IdentityRole<int>> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // ------------------------------------
        // 1. Obtener todos los roles
        // ------------------------------------
        [HttpGet("all")]
        public IActionResult GetAllRoles()
        {
            var roles = _roleManager.Roles.Select(r => new { r.Id, r.Name }).ToList();
            return Ok(roles);
        }

        // ------------------------------------
        // 2. Crear un nuevo rol
        // ------------------------------------
        [HttpPost("create")]
        public async Task<IActionResult> CreateRole(string roleName)
        {
            if (await _roleManager.RoleExistsAsync(roleName))
                return BadRequest($"El rol '{roleName}' ya existe.");

            var result = await _roleManager.CreateAsync(new IdentityRole<int>(roleName));

            if (result.Succeeded)
                return Ok($"Rol '{roleName}' creado.");

            return BadRequest(result.Errors);
        }

        // ------------------------------------
        // 3. Asignar un rol a un usuario
        // ------------------------------------
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRoleToUser(string email, string role)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return NotFound("Usuario no encontrado.");

            if (!await _roleManager.RoleExistsAsync(role))
                return BadRequest($"El rol '{role}' no existe.");

            var result = await _userManager.AddToRoleAsync(user, role);

            if (result.Succeeded)
                return Ok($"Rol '{role}' asignado a {email}");

            return BadRequest(result.Errors);
        }

        // ------------------------------------
        // 4. Remover rol de un usuario
        // ------------------------------------
        [HttpPost("remove")]
        public async Task<IActionResult> RemoveRole(string email, string role)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return NotFound("Usuario no encontrado.");

            var result = await _userManager.RemoveFromRoleAsync(user, role);

            if (result.Succeeded)
                return Ok($"Rol '{role}' removido de {email}");

            return BadRequest(result.Errors);
        }

        // ------------------------------------
        // 5. Obtener roles de un usuario
        // ------------------------------------
        [HttpGet("user/{email}")]
        public async Task<IActionResult> GetUserRoles(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return NotFound("Usuario no encontrado.");

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(roles);
        }
    }
}
