using System.Collections.Generic;
using System.Threading.Tasks;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Services
{
    public interface IIdentityAppService
    {
        Task<AuthenticationResult> RegisterAsync(string email, string password, params KeyValuePair<string,object>[] userParameters);
        
        Task<AuthenticationResult> LoginAsync(string email, string password);
        
        Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken);

        Task<AuthenticationResult> ResetPasswordAsync(string email, string resetToken, string password);

        Task<AuthenticationResult> ForgottenPasswordAsync(string email);
    }
}