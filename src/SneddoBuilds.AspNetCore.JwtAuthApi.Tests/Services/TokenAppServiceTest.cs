using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models;
using SneddoBuilds.AspNetCore.JwtAuthApi.Services;
using SneddoBuilds.AspNetCore.JwtAuthApi.Tests.Helpers;
using Xunit;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Tests.Services
{
    public class TokenAppServiceTest
    {
        private Mock<IClaimsBuilder<IdentityUser, string>> _claimsBuilder = new Mock<IClaimsBuilder<IdentityUser, string>>();
        private Mock<UserManager<IdentityUser>> _identityUserManagerMock = MockHelpers.MockUserManager<IdentityUser>();
        private Mock<RoleManager<IdentityRole>> _identityRoleManagerMock = MockHelpers.MockRoleManager<IdentityRole>();
        private JwtSettings _jwtSettings;
        private TokenValidationParameters _tokenValidationParameters;
        private Mock<ILogger<TokenAppService<IdentityUser, IdentityRole>>> _loggerMock =
            new Mock<ILogger<TokenAppService<IdentityUser, IdentityRole>>>();

        private Mock<JwtSecurityTokenHandler> _tokenHandlerMock = new Mock<JwtSecurityTokenHandler>(); 
        private IdentityUser _identityUser;


        public TokenAppServiceTest()
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
            
        }

        [Fact]
        private async Task GenerateAuthenticationResultForUserAsync_validInputNoRoles_CorrectMethodsCalled()
        {
            var tokenAppService = new TokenAppService<IdentityUser, IdentityRole>(
                _tokenHandlerMock.Object,
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _claimsBuilder.Object);

            var jti = Guid.NewGuid().ToString();
            var result = await tokenAppService.GenerateAuthenticationResultForUserAsync(_identityUser, jti);
            
            Assert.True(result.Success);
            _identityUserManagerMock.Verify(x=>x.GetClaimsAsync(It.IsAny<IdentityUser>()), Times.Once);
            _identityUserManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<IdentityUser>()), Times.Once);
            _identityRoleManagerMock.Verify(x=>x.FindByNameAsync(It.IsAny<string>()), Times.Never);
            _identityRoleManagerMock.Verify(x=>x.GetClaimsAsync(It.IsAny<IdentityRole>()), Times.Never);
            _tokenHandlerMock.Verify(x=>x.CreateToken(It.IsAny<SecurityTokenDescriptor>()), Times.Exactly(2));
            _identityUserManagerMock.Verify(x=>x.SetAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Once);

        }
        
        [Fact]
        private async Task GenerateAuthenticationResultForUserAsync_validInputWithRoles_CorrectMethodsCalled()
        {
            _identityUserManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<IdentityUser>()))
                .ReturnsAsync(new List<string> {"Role1", "Role2"});

            _identityRoleManagerMock.Setup(x => x.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(new IdentityRole("RoleName"));
            
            var tokenAppService = new TokenAppService<IdentityUser, IdentityRole>(
                _tokenHandlerMock.Object,
                _identityUserManagerMock.Object,
                _identityRoleManagerMock.Object,
                _jwtSettings,
                _tokenValidationParameters,
                _loggerMock.Object,
                _claimsBuilder.Object);

            var jti = Guid.NewGuid().ToString();
            var result = await tokenAppService.GenerateAuthenticationResultForUserAsync(_identityUser, jti);
            
            Assert.True(result.Success);
            _identityUserManagerMock.Verify(x=>x.GetClaimsAsync(It.IsAny<IdentityUser>()), Times.Once);
            _identityUserManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<IdentityUser>()), Times.Once);
            _identityRoleManagerMock.Verify(x=>x.FindByNameAsync(It.IsAny<string>()), Times.Exactly(2));
            _identityRoleManagerMock.Verify(x=>x.GetClaimsAsync(It.IsAny<IdentityRole>()), Times.Exactly(2));
            _tokenHandlerMock.Verify(x=>x.CreateToken(It.IsAny<SecurityTokenDescriptor>()), Times.Exactly(2));
            _identityUserManagerMock.Verify(x=>x.SetAuthenticationTokenAsync(It.IsAny<IdentityUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        }
        
        
    }
}