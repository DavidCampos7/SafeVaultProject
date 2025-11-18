using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/test")]
    public class SecureTestController : ControllerBase
    {
        [Authorize]
        [HttpGet("auth")]
        public IActionResult Authenticated()
        {
            return Ok("Eres un usuario autenticado.");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult OnlyAdmins()
        {
            return Ok("Solo Admin puede ver esto.");
        }

        [Authorize(Roles = "Manager")]
        [HttpGet("manager")]
        public IActionResult OnlyManagers()
        {
            return Ok("Solo Manager puede ver esto.");
        }

        [Authorize(Roles = "Admin,Manager")]
        [HttpGet("admin-or-manager")]
        public IActionResult AdminOrManager()
        {
            return Ok("Admin o Manager.");
        }
    }
}
