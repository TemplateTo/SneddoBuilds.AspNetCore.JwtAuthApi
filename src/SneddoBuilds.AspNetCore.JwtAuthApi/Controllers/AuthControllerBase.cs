using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Requests;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;
using SneddoBuilds.AspNetCore.JwtAuthApi.Services;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Controllers
{
    //[Route("{__tenant__}/" + "api/[controller]/[action]")]
    //[Route("api/Auth/[action]")]
    //[ApiController]
    //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AuthControllerBase<TUser> : ControllerBase
    {
        private readonly IIdentityAppService<TUser> _identityAppService;
        private readonly IHttpContextAccessor _contextAccessor;

        public AuthControllerBase(IIdentityAppService<TUser> identityAppService, IHttpContextAccessor contextAccessor)
        {
            _identityAppService = identityAppService;
            _contextAccessor = contextAccessor;
        }
        
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [AllowAnonymous]
        public virtual async Task<ActionResult<UserRegistrationSuccessResponse<TUser>>> Create([FromBody] UserRegistrationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthFailedResponse
                {
                    Errors = ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage))
                });
            }

            var userParamKeyValuePairs =
                request.UserParameters.Select(x => new KeyValuePair<string, string>(x.Name, x.Value));
            
            var authResponse = await _identityAppService.RegisterAsync(request.Email, request.Password, null, userParamKeyValuePairs.ToArray());

            if (!authResponse.Success)
            {
                return BadRequest(new AuthFailedResponse
                {
                    Errors = authResponse.Errors
                });
            }
            
            return Ok(new UserRegistrationSuccessResponse<TUser>
            {
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken,
                User = authResponse.User
            });
        }
        
        [HttpPost]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public virtual async Task<ActionResult<AuthSuccessResponse>> Login([FromBody] UserLoginRequest request)
        {
            var authResponse = await _identityAppService.LoginAsync(request.Email, request.Password);

            if (!authResponse.Success)
            {
                return BadRequest(new AuthFailedResponse
                {
                    Errors = authResponse.Errors
                });
            }
            
            _contextAccessor.HttpContext.Response.Cookies.Append("jwt", authResponse.Token, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                Secure = true
            });
            
            return Ok(new AuthSuccessResponse
            {
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken
            });
        }
        
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public virtual async Task<ActionResult<AuthSuccessResponse>> Refresh([FromBody] RefreshTokenRequest request)
        {
            var authResponse = await _identityAppService.RefreshTokenAsync(request.Token, request.RefreshToken);

            if (!authResponse.Success)
            {
                return BadRequest(new AuthFailedResponse
                {
                    Errors = authResponse.Errors
                });
            }
            
            return Ok(new AuthSuccessResponse
            {
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken
            });
        }

        [AllowAnonymous]
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public virtual async Task<ActionResult<ForgottenPasswordResponse>> ForgottenPassword([FromBody] ForgottenPasswordRequest request)
        {
            var sendForgotPassword = await _identityAppService.ForgottenPasswordAsync(request.Email);
            if (!sendForgotPassword.Success)
            {
                return BadRequest(new AuthFailedResponse
                {
                    Errors = sendForgotPassword.Errors
                });
            }

            return Ok(new ForgottenPasswordResponse
            {
                IsSuccess = true
            });
        }
        
        [AllowAnonymous]
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public virtual async Task<ActionResult<AuthSuccessResponse>> ResetPassword(ResetPasswordRequest request)
        {
            var resetPassword =
                await _identityAppService.ResetPasswordAsync(request.Email, request.ResetToken, request.Password);
            if (!resetPassword.Success)
            {
                return BadRequest(new AuthFailedResponse
                {
                    Errors = resetPassword.Errors
                });
            }
            
            return Ok(new AuthSuccessResponse
            {
                Token = resetPassword.Token,
                RefreshToken = resetPassword.RefreshToken
            });
        }
        
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public virtual ActionResult<AuthSuccessResponse> Logout()
        {
            _contextAccessor.HttpContext.Response.Cookies.Delete("jwt");
            
            return Ok();
        }
        
        
    }
}