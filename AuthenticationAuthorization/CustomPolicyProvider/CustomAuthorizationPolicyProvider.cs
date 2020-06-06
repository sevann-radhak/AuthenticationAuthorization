using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAuthorization.CustomPolicyProvider
{
    public class SecurityLevelAttribute : AuthorizeAttribute
    {
        public SecurityLevelAttribute(int level)
        {
            Policy = $"{DynamicPolicies.SecurityLevel}.{level}";
        }
    }

    public static class DynamicPolicies
    {
        public static IEnumerable<string> Get()
        {
            yield return SecurityLevel;
            yield return Rank;
        }

        public const string SecurityLevel = "SecurityLevel";
        public const string Rank = "Rank";
    }

    public static class DynamicAuthorizationPolicyFactory
    {
        public static AuthorizationPolicy Create(string policyName)
        {
            string type = policyName.Split('.')[0];
            string value = policyName.Split('.')[1];

            switch (type)
            {
                case DynamicPolicies.Rank:
                    return new AuthorizationPolicyBuilder()
                        .RequireClaim(type, value)
                        .Build();

                case DynamicPolicies.SecurityLevel:
                    return new AuthorizationPolicyBuilder()
                        .AddRequirements(new SecurityLevelRequirement(Convert.ToInt32(value)))
                        .Build();

                default:
                    return null;
            }
        }
    }

    public class SecurityLevelRequirement : IAuthorizationRequirement
    {
        public int Level { get; }
        public SecurityLevelRequirement(int level)
        {
            Level = level;
        }
    }

    public class SecurityLevelHandler : AuthorizationHandler<SecurityLevelRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            SecurityLevelRequirement requirement)
        {
            int claimValue = Convert.ToInt32(context.User.Claims
                .FirstOrDefault(x => x.Type == DynamicPolicies.SecurityLevel)
                ?.Value ?? "0");

            if (requirement.Level <= claimValue)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }

    public class CustomAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {

        public CustomAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
        {
        }

        // {type}.{value}
        public override Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            foreach (string customPolicy in DynamicPolicies.Get())
            {
                if (policyName.StartsWith(customPolicy))
                {
                    return Task.FromResult(DynamicAuthorizationPolicyFactory.Create(policyName));
                }
            }

            return base.GetPolicyAsync(policyName);
        }
    }
}
