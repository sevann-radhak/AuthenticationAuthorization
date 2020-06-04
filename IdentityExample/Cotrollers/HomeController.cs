using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NETCore.MailKit.Core;
using System.Threading.Tasks;

namespace IdentityExample.Cotrollers
{
    public class HomeController : Controller
    {
        private readonly IEmailService _emailService;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public HomeController(
            IEmailService emailService,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            _emailService = emailService;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            IdentityUser user = await _userManager.FindByNameAsync(username);
            if (user != null)
            {
                Microsoft.AspNetCore.Identity.SignInResult signInResult = await _signInManager.PasswordSignInAsync(user, password, false, false);
                if (signInResult.Succeeded)
                {
                    return RedirectToAction(nameof(Index));
                }
            }
            else
            {
                return NotFound();
            }

            return RedirectToAction(nameof(Index));
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string username, string password)
        {
            IdentityUser user = new IdentityUser
            {
                Email = username,
                UserName = username
            };

            IdentityResult result = await _userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                // generation of the email token
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var link = Url.Action(
                    nameof(VerifyEmail), 
                    "Home", 
                    new { userId = user.Id, code },
                    Request.Scheme,
                    Request.Host.ToString());

                //await _emailService.SendAsync(
                //    "macri@yopmail.com", 
                //    "Email veriry", 
                //    $"<a href=\"{link}\">Verify email</a>", 
                //    true);

                //return RedirectToAction(nameof(EmailVerification));

                var userCreated = await _userManager.FindByIdAsync(user.Id);
                
                if (userCreated == null) return BadRequest();

                var confirmEmail = await _userManager.ConfirmEmailAsync(userCreated, code);

                if(confirmEmail.Succeeded)
                {
                    return View(nameof(VerifyEmail));
                }
                else
                {
                    return BadRequest();
                }
            }
            return RedirectToAction(nameof(Index));
        }

        public IActionResult VerifyEmail(string userId, string code)
        {
            return View();
        }

        public IActionResult EmailVerification => View();

        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Index));
        }
    }
}