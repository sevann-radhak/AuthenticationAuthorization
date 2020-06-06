using AuthenticationAuthorization.CustomPolicyProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationAuthorization.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        [Authorize(Policy = "Claim.DoB")]
        public IActionResult SecretPolicy()
        {
            return View(nameof(Secret));
        }

        [Authorize(Roles = "Admin")]
        public IActionResult SecretRole()
        {
            return View(nameof(Secret));
        }

        [SecurityLevel(5)]
        public IActionResult SecretLevel()
        {
            return View(nameof(Secret));
        }

        [SecurityLevel(10)]
        public IActionResult SecretHigherLevel()
        {
            return View(nameof(Secret));
        }

        [AllowAnonymous]
        public IActionResult Authenticate()
        {
            List<Claim> grandmaClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@gmail.com"),
                new Claim(ClaimTypes.DateOfBirth, "11/11/2000"),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(DynamicPolicies.SecurityLevel, "7"),
                new Claim("Grandma.Says", "Very nice page.")
            };

            List<Claim> licenseClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob K Foo"),
                new Claim("DrivingLicense", "A+")
            };

            ClaimsIdentity grandmaIdentity = new ClaimsIdentity(grandmaClaims, "Grandma Identity");
            ClaimsIdentity licenseIdentity = new ClaimsIdentity(licenseClaims, "Goverment");

            ClaimsPrincipal userPrincipal = new ClaimsPrincipal(new[] { grandmaIdentity, licenseIdentity });

            HttpContext.SignInAsync(userPrincipal);

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> DoStuff([FromServices] IAuthorizationService authorizationService)
        {
            AuthorizationPolicyBuilder builder = new AuthorizationPolicyBuilder("Schema");
            AuthorizationPolicy customPolicy = builder.RequireClaim("Hello").Build();
            AuthorizationResult authResult = await authorizationService.AuthorizeAsync(User, customPolicy);

            if (authResult.Succeeded)
            {
                return View(nameof(Index));
            }

            return View(nameof(Index));
        }
    }
}