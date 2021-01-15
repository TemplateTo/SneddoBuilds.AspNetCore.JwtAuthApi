using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Services
{
    public class TokenAppService<TUser, TRole> : ITokenAppService<TUser> 
        where TUser : IdentityUser 
        where TRole : IdentityRole
    {
        private readonly UserManager<TUser> _userManager;
        private readonly RoleManager<TRole> _roleManager;
        private readonly JwtSettings _jwtSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly ILogger<TokenAppService<TUser, TRole>> _logger;
        private readonly JwtSecurityTokenHandler _tokenHandler;

        public TokenAppService(JwtSecurityTokenHandler tokenHandler, UserManager<TUser> userManager, RoleManager<TRole> roleManager, JwtSettings jwtSettings, TokenValidationParameters tokenValidationParameters, ILogger<TokenAppService<TUser, TRole>> logger)
        {
            _tokenHandler = tokenHandler;
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtSettings = jwtSettings;
            _tokenValidationParameters = tokenValidationParameters;
            _logger = logger;
        }

        public async Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(TUser user, string jti = null)
        {
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var refreshKey = Encoding.ASCII.GetBytes(_jwtSettings.RefreshSecret);
            jti ??= Guid.NewGuid().ToString();
            
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("id", user.Id)
            };

            var userClaims = await _userManager.GetClaimsAsync(user);
            if(userClaims!= null && userClaims.Any())
                claims.AddRange(userClaims);
    
            var userRoles = await _userManager.GetRolesAsync(user);
            if (userRoles != null && userRoles.Any())
            {
                foreach (var userRole in userRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole));
                    var role = await _roleManager.FindByNameAsync(userRole);
                    if (role == null) continue;
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    if(roleClaims==null) continue;
                    foreach (var roleClaim in roleClaims)
                    {
                        if (claims.Contains(roleClaim))
                            continue;

                        claims.Add(roleClaim);
                    }
                }
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.Add(_jwtSettings.TokenLifetime),
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _tokenHandler.CreateToken(tokenDescriptor);
            
            // Create refreshtoken
            var refreshClaims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Jti, jti),
            };
            
            var tokenDescriptorRefresh = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(refreshClaims),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMonths(6),
                
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(refreshKey), SecurityAlgorithms.HmacSha256Signature),
            };

            var refreshToken = _tokenHandler.CreateToken(tokenDescriptorRefresh);

            await _userManager.SetAuthenticationTokenAsync(user, "SneddoBuilds.AspNetCore.JwtAuth", "RefreshToken", _tokenHandler.WriteToken(refreshToken));

            return new AuthenticationResult
            {
                Success = true,
                Token = _tokenHandler.WriteToken(token),
                RefreshToken = _tokenHandler.WriteToken(refreshToken)
            };
        }

        public bool IsJwtWithValidSecurityAlgorithm(SecurityToken validatedToken)
        {
            return (validatedToken is JwtSecurityToken jwtSecurityToken) &&
                   jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                       StringComparison.InvariantCultureIgnoreCase);
        }

        public ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            try
            {
                var tokenValidationParameters = _tokenValidationParameters.Clone();
                tokenValidationParameters.ValidateLifetime = false;
                var principal = _tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
                if (!IsJwtWithValidSecurityAlgorithm(validatedToken))
                {
                    return null;
                }

                return principal;
            }
            catch
            {
                return null;
            }
        }
    }
}