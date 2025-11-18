using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models;

public partial class User : IdentityUser<int>
{
    //Ya se hereda Id, UserName, PasswordHash, etc desde IdentityUser
}
