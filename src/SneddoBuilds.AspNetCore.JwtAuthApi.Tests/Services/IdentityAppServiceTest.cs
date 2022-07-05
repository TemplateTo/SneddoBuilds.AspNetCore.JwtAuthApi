using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses;
using SneddoBuilds.AspNetCore.JwtAuthApi.Services;
using SneddoBuilds.AspNetCore.JwtAuthApi.Tests.Helpers;
using Xunit;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Tests.Services
{
    public class AppUser : IdentityUser
    {
        public string FullName { get; set; }
    }
    
    public class IdentityAppServiceTest
    {
        private Mock<UserManager<IdentityUser>> _identityUserManagerMock = MockHelpers.MockUserManager<IdentityUser>();
        private Mock<UserManager<AppUser>> _identityAppUserManagerMock = MockHelpers.MockUserManager<AppUser>();
        private Mock<RoleManager<IdentityRole>> _identityRoleManagerMock = MockHelpers.MockRoleManager<IdentityRole>();
        private Mock<ITokenAppService<IdentityUser>> _tokenAppServiceMock = new Mock<ITokenAppService<IdentityUser>>();
        private Mock<ITokenAppService<AppUser>> _appUsertokenAppServiceMock = new Mock<ITokenAppService<AppUser>>();
        private JwtSettings _jwtSettings;
        private TokenValidationParameters _tokenValidationParameters;
        private Mock<ILogger<IdentityAppService<IdentityUser, IdentityRole>>> _loggerMock =
            new Mock<ILogger<IdentityAppService<IdentityUser, IdentityRole>>>();
        private Mock<ILogger<IdentityAppService<AppUser, IdentityRole>>> _loggerAppUserMock =
            new Mock<ILogger<IdentityAppService<AppUser, IdentityRole>>>();

        private Mock<IEmailSender> _emailSender = new Mock<IEmailSender>();
        
        
        private IdentityUser _identityUser;
        
        public IdentityAppServiceTest()
        {
            _jwtSettings = new JwtSettings
            {
                Secret = "secretaaaaaaaaaaaaaaaaaaaa",
                RefreshSecret = "RefreshSecretaaaaaaaaaaaaaa",
                TokenLifetime = TimeSpan.FromDays(1),
                EmailSettings = new EmailSettings
                {
                    ForgotPasswordBody = "Some Body Text with a {{token}}",
                    ForgotPasswordSubject = "Forgotten password subject",
                    FromEmail = "Test@test.test"
                }
            };
            
            _identityUser = new IdentityUser
            {
                Email = "test@test.com",
                UserName = "test@test.com"
            };

            _tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = false,
                ValidateLifetime = true
            };

            _tokenAppServiceMock.Setup(x => x.GenerateAuthenticationResultForUserAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(() => new AuthenticationResult
                    {Success = true, Token = "standardtoken", RefreshToken = "refreshToken"});
            
            _appUsertokenAppServiceMock.Setup(x => x.GenerateAuthenticationResultForUserAsync(It.IsAny<AppUser>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(() => new AuthenticationResult
                    {Success = true, Token = "standardtoken", RefreshToken = "refreshToken"});
        }
        
        [Fact]
        public async Task RegisterAsync_IdentityUser_Adds()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => null);
            _identityUserManagerMock.Setup(x => x.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => IdentityResult.Success);
            _identityUserManagerMock.Setup(x => x.GetClaimsAsync(It.IsAny<IdentityUser>()))
                .ReturnsAsync(() => new List<Claim>());
            _identityUserManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<IdentityUser>()))
                .ReturnsAsync(() => new List<string>());
            
            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RegisterAsync("test@test.com", "Pa55w0rd");
            
            Assert.True(result.Success);
        }
        
        [Fact]
        public async Task RegisterAsync_ExistingUser_Fails()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RegisterAsync("test@test.com", "Pa55w0rd");
            
            Assert.False(result.Success);
            Assert.Matches("User with this email address already exists", result.Errors.First());
        }
        
        [Fact]
        public async Task RegisterAsync_IdentityUserCreateFails_Fails()
        {
            var identityError = new IdentityError();
            identityError.Description = "Failed";
            
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => null);
            _identityUserManagerMock.Setup(x => x.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => IdentityResult.Failed(new []{ identityError}));

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RegisterAsync("test@test.com", "Pa55w0rd");
            
            Assert.False(result.Success);
            Assert.Equal("Failed", result.Errors.First());
        }
        
        [Fact]
        public async Task RegisterAsync_AppUserCreateWithParam_Succeed()
        {
            AppUser appUser = null;
            
            _identityAppUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => null);
            _identityAppUserManagerMock.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                .ReturnsAsync(() => IdentityResult.Success).Callback<AppUser, string>((user, pass) => appUser = user);

            var identityAppService = new IdentityAppService<AppUser, IdentityRole>(
                _identityAppUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerAppUserMock.Object,
                _appUsertokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RegisterAsync("test@test.com", "Pa55w0rd", null,new []{ new KeyValuePair<string, string>("FullName", "test user")});
            
            Assert.True(result.Success);
            Assert.NotNull(appUser);
            Assert.Equal("test user", appUser.FullName);
        }
        
        [Fact]
        public async Task LoginAsync_IdentityUserCorrectPassword_Pass()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);
            _identityUserManagerMock.Setup(x => x.CheckPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => true);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.LoginAsync("test@test.com", "Pa55w0rd");
            
            Assert.True(result.Success);
        }
        
        [Fact]
        public async Task LoginAsync_IdentityUserIncorrectPassword_Fail()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);
            _identityUserManagerMock.Setup(x => x.CheckPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => false);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.LoginAsync("test@test.com", "Pa55w0rd");
            
            Assert.False(result.Success);
            Assert.Equal("User/password combination is wrong", result.Errors.First());
        }
        
        [Fact]
        public async Task RefreshTokenAsync_NullClaimsPrinciple_Fails()
        {
            _tokenAppServiceMock.Setup(x => x.GetPrincipalFromToken(It.IsAny<string>())).Returns(() => null);
            
            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RefreshTokenAsync("token", "refreshToken");
            
            Assert.False(result.Success);
            Assert.Equal("Invalid Token", result.Errors.First());
        }
        
        [Fact]
        public async Task RefreshTokenAsync_WithClaimsPrinciple_Pass()
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, "test@test.com"),
                new Claim(JwtRegisteredClaimNames.Jti, "jti"),
                new Claim(JwtRegisteredClaimNames.Email, "test@test.com"),
                new Claim("id", "UserId")
            };
            
            var tokenDescriptorRefresh = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMonths(6),
                
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.RefreshSecret)), SecurityAlgorithms.HmacSha256Signature),
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            var refreshToken = tokenHandler.CreateToken(tokenDescriptorRefresh);
            DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var expDate =
                ((Int64) DateTime.Now.Add(_jwtSettings.TokenLifetime).Subtract(UnixEpoch).TotalSeconds).ToString(System.Globalization
                    .CultureInfo.InvariantCulture);
            
            claims.Add(new Claim(JwtRegisteredClaimNames.Exp, expDate));

            var identity = new ClaimsIdentity(claims);
            var claimsPrincipal = new ClaimsPrincipal(identity);

            _identityUserManagerMock.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);
            _identityUserManagerMock.Setup(x => x.CheckPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => false);
            _identityUserManagerMock.Setup(x => x.GetAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(tokenHandler.WriteToken(refreshToken));
            _identityUserManagerMock.Setup(x => x.RemoveAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
            _tokenAppServiceMock.Setup(x => x.GetPrincipalFromToken(It.IsAny<string>())).Returns(() => claimsPrincipal);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RefreshTokenAsync("token", tokenHandler.WriteToken(refreshToken));
            
            Assert.True(result.Success);
        }
        
        [Fact]
        public async Task RefreshTokenAsync_WithClaimsRefreshTokensDontMatch_Fails()
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, "test@test.com"),
                new Claim(JwtRegisteredClaimNames.Jti, "jti"),
                new Claim(JwtRegisteredClaimNames.Email, "test@test.com"),
                new Claim("id", "UserId")
            };
            
            var tokenDescriptorRefresh = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMonths(6),
                
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.RefreshSecret)), SecurityAlgorithms.HmacSha256Signature),
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            var refreshToken = tokenHandler.CreateToken(tokenDescriptorRefresh);
            DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var expDate =
                ((Int64) DateTime.Now.Add(_jwtSettings.TokenLifetime).Subtract(UnixEpoch).TotalSeconds).ToString(System.Globalization
                    .CultureInfo.InvariantCulture);
            
            claims.Add(new Claim(JwtRegisteredClaimNames.Exp, expDate));

            var identity = new ClaimsIdentity(claims);
            var claimsPrincipal = new ClaimsPrincipal(identity);

            _identityUserManagerMock.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);
            _identityUserManagerMock.Setup(x => x.CheckPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => false);
            _identityUserManagerMock.Setup(x => x.GetAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(tokenHandler.WriteToken(refreshToken));
            _identityUserManagerMock.Setup(x => x.RemoveAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
            _tokenAppServiceMock.Setup(x => x.GetPrincipalFromToken(It.IsAny<string>())).Returns(() => claimsPrincipal);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RefreshTokenAsync("token", "tokenHandler.WriteToken(refreshToken)");
            
            Assert.False(result.Success);
            Assert.Equal("This refresh token is not valid", result.Errors.First());
        }
        
        // TODO: workout how to create a token with an expiry in the past to test expired token.
        // [Fact]
        // public async Task RefreshTokenAsync_WithClaimsRefreshTokens_Expired_Fails()
        // {
        //     var claims = new List<Claim>
        //     {
        //         new Claim(JwtRegisteredClaimNames.Sub, "test@test.com"),
        //         new Claim(JwtRegisteredClaimNames.Jti, "jti"),
        //         new Claim(JwtRegisteredClaimNames.Email, "test@test.com"),
        //         new Claim("id", "UserId")
        //     };
        //     
        //     var tokenDescriptorRefresh = new SecurityTokenDescriptor
        //     {
        //         Subject = new ClaimsIdentity(claims),
        //         IssuedAt = DateTime.UtcNow.Subtract(new TimeSpan(2,0,0,0)),
        //         Expires = DateTime.UtcNow.Subtract(new TimeSpan(1,0,0,0)),
        //         
        //         SigningCredentials =
        //             new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.RefreshSecret)), SecurityAlgorithms.HmacSha256Signature),
        //     };
        //     var tokenHandler = new JwtSecurityTokenHandler();
        //
        //     var refreshToken = tokenHandler.CreateToken(tokenDescriptorRefresh);
        //     DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        //     var expDate =
        //         ((Int64) DateTime.Now.Add(_jwtSettings.TokenLifetime).Subtract(UnixEpoch).TotalSeconds).ToString(System.Globalization
        //             .CultureInfo.InvariantCulture);
        //     
        //     claims.Add(new Claim(JwtRegisteredClaimNames.Exp, expDate));
        //
        //     var identity = new ClaimsIdentity(claims);
        //     var claimsPrincipal = new ClaimsPrincipal(identity);
        //
        //     _identityUserManagerMock.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);
        //     _identityUserManagerMock.Setup(x => x.CheckPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => false);
        //     _identityUserManagerMock.Setup(x => x.GetAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(tokenHandler.WriteToken(refreshToken));
        //     _identityUserManagerMock.Setup(x => x.RemoveAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
        //     _tokenAppServiceMock.Setup(x => x.GetPrincipalFromToken(It.IsAny<string>())).Returns(() => claimsPrincipal);
        //
        //     var identityAppService = new IdentityAppService(
        //         _identityUserManagerMock.Object,
        //         _identityRoleManagerMock.Object,
        //         _jwtSettings,
        //         _tokenValidationParameters,
        //         _loggerMock.Object,
        //         _tokenAppServiceMock.Object
        //     );
        //
        //     var result = await identityAppService.RefreshTokenAsync("token", tokenHandler.WriteToken(refreshToken));
        //     
        //     Assert.False(result.Success);
        //     Assert.Equal("This refresh token has expired", result.Errors.First());
        // }
        
        [Fact]
        public async Task RefreshTokenAsync_WithClaimsJTIDoesNotMatch_Fails()
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, "test@test.com"),
                new Claim(JwtRegisteredClaimNames.Jti, "jti"),
                new Claim(JwtRegisteredClaimNames.Email, "test@test.com"),
                new Claim("id", "UserId")
            };
            
            var tokenDescriptorRefresh = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMonths(6),
                
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.RefreshSecret)), SecurityAlgorithms.HmacSha256Signature),
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            var refreshToken = tokenHandler.CreateToken(tokenDescriptorRefresh);
            DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var expDate =
                ((Int64) DateTime.Now.Add(_jwtSettings.TokenLifetime).Subtract(UnixEpoch).TotalSeconds).ToString(System.Globalization
                    .CultureInfo.InvariantCulture);
            
            claims.Add(new Claim(JwtRegisteredClaimNames.Exp, expDate));
            var jtiClaim = claims.Find(x => x.Type == JwtRegisteredClaimNames.Jti);
            claims.Remove(jtiClaim);
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, "jtinew"));

            var identity = new ClaimsIdentity(claims);
            var claimsPrincipal = new ClaimsPrincipal(identity);

            _identityUserManagerMock.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(() => _identityUser);
            _identityUserManagerMock.Setup(x => x.CheckPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>())).ReturnsAsync(() => false);
            _identityUserManagerMock.Setup(x => x.GetAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(tokenHandler.WriteToken(refreshToken));
            _identityUserManagerMock.Setup(x => x.RemoveAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
            _tokenAppServiceMock.Setup(x => x.GetPrincipalFromToken(It.IsAny<string>())).Returns(() => claimsPrincipal);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.RefreshTokenAsync("token", tokenHandler.WriteToken(refreshToken));
            
            Assert.False(result.Success);
            Assert.Equal("This refresh token does not match this JWT", result.Errors.First());
        }
        
        [Fact]
        public async Task ForgotPasswordAsync_UserNotFound_ReturnTrue()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => null);
            

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.ForgottenPasswordAsync("test@test.com");
            
            Assert.True(result.Success);
            _identityUserManagerMock.Verify(m=> m.GeneratePasswordResetTokenAsync(It.IsAny<IdentityUser>()), Times.Never);
            _emailSender.Verify(m=>m.SendEmailAsync(It.IsAny<string>(),It.IsAny<string>(),It.IsAny<string>()), Times.Never);
        }
        
        [Fact]
        public async Task ForgotPasswordAsync_UserFound_ReturnTrue()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(_identityUser);
            _identityUserManagerMock.Setup(x => x.GeneratePasswordResetTokenAsync(It.IsAny<IdentityUser>()))
                .ReturnsAsync("token");


            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.ForgottenPasswordAsync("test@test.com");
            
            Assert.True(result.Success);
            _identityUserManagerMock.Verify(m=> m.GeneratePasswordResetTokenAsync(It.IsAny<IdentityUser>()), Times.Once);
            _emailSender.Verify(m=>m.SendEmailAsync(It.IsAny<string>(),It.IsAny<string>(),It.IsAny<string>()), Times.Once);
        }
        
        [Fact]
        public async Task ResetPasswordAsync_AllOK_ReturnTrue()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(_identityUser);
            _identityUserManagerMock.Setup(x => x.ResetPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);
            
            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.ResetPasswordAsync("test@test.com", "restToken", "Password");
            
            Assert.True(result.Success);
            _identityUserManagerMock.Verify(m=> m.ResetPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()), 
                Times.Once);
            _tokenAppServiceMock.Verify(m => m.GenerateAuthenticationResultForUserAsync(It.IsAny<IdentityUser>(), null, null),
                Times.Once);
        }
        
        [Fact]
        public async Task ResetPasswordAsync_UserNotFound_ReturnTrue()
        {
            _identityUserManagerMock.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(()=>null);

            var identityAppService = new IdentityAppService(
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _tokenAppServiceMock.Object,
                _emailSender.Object
            );

            var result = await identityAppService.ResetPasswordAsync("test@test.com", "restToken", "Password");
            
            Assert.True(result.Success);
            _identityUserManagerMock.Verify(m=> m.ResetPasswordAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>()), 
                Times.Never);
            _tokenAppServiceMock.Verify(m => m.GenerateAuthenticationResultForUserAsync(It.IsAny<IdentityUser>(), null, null),
                Times.Never);
        }
        
        
    }
}