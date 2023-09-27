using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthClient.Web.Controllers;

[Authorize]
public class AuthController : Controller
{
    public IActionResult Index()
    {
        return Content("OK");
    }
}