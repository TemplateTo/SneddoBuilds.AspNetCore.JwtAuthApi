using System.Collections.Generic;
using System.Threading.Tasks;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Services
{
    public interface IIdentityAppService<TUser>
    {
        Task<RegisterResult<TUser>> RegisterAsync(string email, string password, string companyId = null, params KeyValuePair<string,string>[] userParameters);
        
        Task<AuthenticationResult> LoginAsync(string email, string password, string companyId = null);
        
        Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken, string companyId = null);

        Task<AuthenticationResult> ResetPasswordAsync(string email, string resetToken, string password);

        Task<AuthenticationResult> ForgottenPasswordAsync(string email, string subject = "", string body = "");

        Task<AuthenticationResult> AddClaimsAsync(string email, KeyValuePair<string, string>[] claims);
    }
}