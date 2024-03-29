﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Services
{
    public class IdentityAppService : IdentityAppService<IdentityUser, IdentityRole>
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JwtSettings _jwtSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly ITokenAppService<IdentityUser> _tokenAppService;
        private readonly ILogger<IdentityAppService<IdentityUser, IdentityRole>> _logger;
        private readonly IEmailSender _emailSender;
        
        public IdentityAppService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, JwtSettings jwtSettings, TokenValidationParameters tokenValidationParameters, ILogger<IdentityAppService<IdentityUser, IdentityRole>> logger, ITokenAppService<IdentityUser> tokenAppService, IEmailSender emailSender) 
            : base(userManager, roleManager, jwtSettings,tokenValidationParameters, logger, tokenAppService, emailSender)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtSettings = jwtSettings;
            _tokenValidationParameters = tokenValidationParameters;
            _logger = logger;
            _tokenAppService = tokenAppService;
            _emailSender = emailSender;
        }
    }
    
    public class IdentityAppService<TUser, TRole> : IIdentityAppService<TUser>
            where TUser : IdentityUser
            where TRole : IdentityRole
        {
            
        private readonly UserManager<TUser> _userManager;
        private readonly RoleManager<TRole> _roleManager;
        private readonly JwtSettings _jwtSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly ITokenAppService<TUser> _tokenAppService;
        private readonly ILogger<IdentityAppService<TUser, TRole>> _logger;
        private readonly IEmailSender _emailSender;

        public IdentityAppService(UserManager<TUser> userManager, RoleManager<TRole> roleManager, JwtSettings jwtSettings, TokenValidationParameters tokenValidationParameters, ILogger<IdentityAppService<TUser, TRole>> logger, ITokenAppService<TUser> tokenAppService, IEmailSender emailSender)
        {
            _userManager = userManager;
            _jwtSettings = jwtSettings;
            _tokenValidationParameters = tokenValidationParameters;
            _roleManager = roleManager;
            _logger = logger;
            _tokenAppService = tokenAppService;
            _emailSender = emailSender;
        }
        
        public async Task<RegisterResult<TUser>> RegisterAsync(string email, string password, string companyId = null, params KeyValuePair<string,string>[] userParameters)
        {
            var existingUser = await _userManager.FindByEmailAsync(email);
            
            if (existingUser != null)
            {
                return new RegisterResult<TUser>
                {
                    Errors = new[] {"User with this email address already exists"}
                };
            }

            var newUser = (TUser) Activator.CreateInstance(typeof(TUser)); 
            newUser.Email = email;
            newUser.UserName = email;
            MapUserParameters(newUser, userParameters);
            
            var createdUser = await _userManager.CreateAsync(newUser, password);

            if (!createdUser.Succeeded)
            {
                return new RegisterResult<TUser>
                {
                    Errors = createdUser.Errors.Select(x => x.Description)
                };
            }
            
            var authResponse =await _tokenAppService.GenerateAuthenticationResultForUserAsync(newUser, companyId);
            var result = new RegisterResult<TUser>
            {
                Errors = authResponse.Errors,
                Success = authResponse.Success,
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken,
                User = newUser
            };

            return result;
        }

        public async Task<AuthenticationResult> AddClaimsAsync(string email, KeyValuePair<string, string>[] claims)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] {"User does not exist"}
                };
            }

            if (claims.Length > 0)
            {
                for (int i = 0; i < claims.Length; i++)
                {

                    await _userManager.AddClaimAsync(user, new Claim(claims[i].Key, claims[i].Value));
                }
            }
            
            //Returns a new token with the added claims.
            return await _tokenAppService.GenerateAuthenticationResultForUserAsync(user);
        }

        private void MapUserParameters(TUser user, KeyValuePair<string, string>[] userParameters)
        {
            if (userParameters == null || userParameters.Length == 0)
                return;
            
            var userType = user.GetType();
            foreach (var parameter in userParameters)
            {
                var propType = userType.GetProperty(parameter.Key)?.PropertyType;
                var converter = TypeDescriptor.GetConverter(propType);
                var convertedObject = converter.ConvertFromString(parameter.Value);
                
                var prop = userType.GetProperty(parameter.Key);
                prop.SetValue(user, converter.ConvertFromString(parameter.Value));
            }
        }
        
        public async Task<AuthenticationResult> LoginAsync(string email, string password, string companyId = null)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] {"User does not exist"}
                };
            }

            var userHasValidPassword = await _userManager.CheckPasswordAsync(user, password);

            if (!userHasValidPassword)
            {
                return new AuthenticationResult
                {
                    Errors = new[] {"User/password combination is wrong"}
                };
            }
            
            return await _tokenAppService.GenerateAuthenticationResultForUserAsync(user, companyId);
        }

        public async Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken, string companyId = null)
        {
            var validatedToken = _tokenAppService.GetPrincipalFromToken(token);

            if (validatedToken == null)
            {
                return new AuthenticationResult {Errors = new[] {"Invalid Token"}};
            }
            
            var userId = validatedToken.Claims.Single(x => x.Type == "id").Value;
            var user = await _userManager.FindByIdAsync(userId);

            var expiryDateUnix =
                long.Parse(validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            
            var expiryDateTimeUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(expiryDateUnix);

            var jti = validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

            var storedRefreshTokenValue = await _userManager.GetAuthenticationTokenAsync(user, "SneddoBuilds.AspNetCore.JwtAuth", "RefreshToken");

            var storedRefreshToken = new JwtSecurityToken(storedRefreshTokenValue);

            if (storedRefreshTokenValue == null)
            {
                return new AuthenticationResult {Errors = new[] {"This refresh token does not exist"}};
            }
            
            if (!string.Equals(storedRefreshTokenValue, refreshToken))
            {
                return new AuthenticationResult {Errors = new[] {"This refresh token is not valid"}};
            }
            
            if (DateTime.UtcNow > storedRefreshToken.ValidTo)
            {
                return new AuthenticationResult {Errors = new[] {"This refresh token has expired"}};
            }

            if (storedRefreshToken.Claims.Single(x=> x.Type == "jti").Value != jti)
            {
                return new AuthenticationResult {Errors = new[] {"This refresh token does not match this JWT"}};
            }

            //Remove the Refresh token as its now been used.
            await _userManager.RemoveAuthenticationTokenAsync(user, "SneddoBuilds.AspNetCore.JwtAuth", "RefreshToken");
            
            return await _tokenAppService.GenerateAuthenticationResultForUserAsync(user, companyId);
        }

        public async Task<AuthenticationResult> ForgottenPasswordAsync(string email, string subject ="", string body="")
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                //Always returning true here, Dont want to give away account details that includes if one may or may
                //not exist for a given email address.
                return new AuthenticationResult
                {
                    Success = true
                    //Errors = new[] {"User does not exist"}
                };
            }
            
            //Get a reset token
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            _logger.LogDebug($"Reset Token: {resetToken}");
            
            //email reset token
            string emailSubject = string.IsNullOrEmpty(subject)
                ? _jwtSettings.EmailSettings.ForgotPasswordSubject
                : subject;
            string emailBody;
            if (string.IsNullOrEmpty(body))
            {
                emailBody = _jwtSettings.EmailSettings.ForgotPasswordBody.Replace("{{token}}", resetToken);
            }
            else
            {
                emailBody = body.Replace("{{token}}", resetToken);
            }

            await _emailSender.SendEmailAsync(
                user.Email,
                emailSubject,
                emailBody);
            
            return new AuthenticationResult
            {
                Success = true
            };
        }

        public async Task<AuthenticationResult> ResetPasswordAsync(string email, string resetToken, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new AuthenticationResult
                {
                    //Always returning true here, Dont want to give away account details that includes if one may or may
                    //not exist for a given email address.
                    Success = true
                    //Errors = new[] {"User does not exist"}
                };
            }
            
            //Todo: test if _userManager leaks user account existence or not.
            var result = await _userManager.ResetPasswordAsync(user, resetToken, password);
            
            if (!result.Succeeded)
            {
                return new AuthenticationResult
                {
                    Errors = result.Errors.Select(x => x.Description)
                };
            }
            
            return await _tokenAppService.GenerateAuthenticationResultForUserAsync(user);
        }
        
    }
}