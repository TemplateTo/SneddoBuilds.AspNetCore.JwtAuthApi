using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SneddoBuilds.AspNetCore.AuthApi.Controllers;
using SneddoBuilds.AspNetCore.AuthApi.Services;

namespace WebApplication1.Controllers
{
    //TODO: 04 -- Inherit from the base controller and set the attributes.
    [Route("api/Auth/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AuthController : AuthControllerBase
    {
        private readonly IIdentityAppService _identityAppService;

        public AuthController(IIdentityAppService identityAppService) : base(identityAppService)
        {
            _identityAppService = identityAppService;
        }
    }
}