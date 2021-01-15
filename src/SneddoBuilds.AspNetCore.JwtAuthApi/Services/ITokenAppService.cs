using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Services
{
    public interface ITokenAppService<TUser>
    {
        Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(TUser user, string jti = null);
        bool IsJwtWithValidSecurityAlgorithm(SecurityToken validatedToken);
        ClaimsPrincipal GetPrincipalFromToken(string token);
    }
}