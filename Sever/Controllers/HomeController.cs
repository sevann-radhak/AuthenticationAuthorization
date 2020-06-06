using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Sever;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Server.Controllers
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

        public IActionResult Authenticate()
        {
            Claim[] claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                new Claim("granny", "cookie")
            };

            byte[] secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            SymmetricSecurityKey key = new SymmetricSecurityKey(secretBytes);
            string algorithm = SecurityAlgorithms.HmacSha256;

            SigningCredentials sigingCredentials = new SigningCredentials(key, algorithm);

            JwtSecurityToken token = new JwtSecurityToken(
                Constants.Issuer,
                Constants.Audiance,
                claims,
                DateTime.Now,
                DateTime.Now.AddDays(1),
                sigingCredentials
                );

            string tokenJson = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new { access_token = tokenJson });
        }

        public IActionResult Decode(string part)
        {
            byte[] bytes = Convert.FromBase64String(part);
            return Ok(Encoding.UTF8.GetString(bytes));
        }
    }
}