using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SneddoBuilds.AspNetCore.JwtAuthApi.Controllers;
using SneddoBuilds.AspNetCore.JwtAuthApi.Services;

namespace WebApplication1.Controllers
{
    //TODO: 04 -- Inherit from the base controller and set the attributes.
    [Route("api/Auth/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AuthController : AuthControllerBase
    {
        private readonly IIdentityAppService _identityAppService;
        private readonly IHttpContextAccessor _contextAccessor;

        public AuthController(IIdentityAppService identityAppService, IHttpContextAccessor contextAccessor) : base(identityAppService, contextAccessor)
        {
            _identityAppService = identityAppService;
            _contextAccessor = contextAccessor;
        }
    }
}