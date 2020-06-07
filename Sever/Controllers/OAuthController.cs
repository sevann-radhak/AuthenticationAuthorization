using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Sever;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Server.Controllers
{
    public class OAuthController : Controller
    {
        [HttpGet]
        public IActionResult Authorize(
            string response_type,   // authorization flow type
            string client_id,       // client id
            string redirect_uri,
            string scope,           // what info I want
            string state)           // random string generated to confirm that we are going to back to the same client

        {
            // a=foo&b=bar
            QueryBuilder query = new QueryBuilder
            {
                { "redirect_uri", redirect_uri },
                { "state", state }
            };

            return View(model: query.ToString());
        }

        [HttpPost]
        public IActionResult Authorize(
            string username,
            string redirect_uri,
            string state)
        {
            const string code = "SevannSevannSevann";

            // a=foo&b=bar
            QueryBuilder query = new QueryBuilder
            {
                { "code", code },
                { "state", state }
            };

            return RedirectToAction("Token", "oauth",
                new { redirect_uri, code, state });
        }

        [HttpGet]
        public async Task<IActionResult> Token(
            string grant_type,      // flow of access_token request
            string code,            // confirmation of te authentication process
            string redirect_uri,
            string client_id)
        {
            // some mechanism for validating the code
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

            string access_token = new JwtSecurityTokenHandler().WriteToken(token);
            // end some mechanism for validating the code

            var responseObject = new
            {
                access_token,
                token_type = "Bearer",
                raw_claim = "oauthTutorial"
            };

            string responseJson = JsonConvert.SerializeObject(responseObject);
            byte[] responseBytes = Encoding.UTF8.GetBytes(responseJson);

            await Response.Body.WriteAsync(responseBytes, 0, responseBytes.Length);

            return Redirect(redirect_uri);
        }
    }
}