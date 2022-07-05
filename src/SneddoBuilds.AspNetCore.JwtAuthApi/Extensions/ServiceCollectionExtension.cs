using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models;
using SneddoBuilds.AspNetCore.JwtAuthApi.Services;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Extensions
{
    public static class ServiceCollectionExtension
    {
        public static IServiceCollection AddSneddoJwtAuth(this IServiceCollection services, IConfiguration configuration)
        {
            
            Func<IdentityUser, string, List<Claim>> emptyBuilder = delegate(IdentityUser user, string companyId) { return new List<Claim>(); };
            
            return services.AddSneddoJwtAuth<IdentityUser, IdentityRole, FakeDbContext>(configuration, new ClaimsBuilder<IdentityUser, string>
            {
                builder = emptyBuilder
            });
        }

        public static IServiceCollection AddSneddoJwtAuth<TUser, TRole, TDbContext>(this IServiceCollection services,
            IConfiguration configuration, IClaimsBuilder<TUser, string> claimsBuilder)
            where TUser : IdentityUser
            where TRole : IdentityRole
            where TDbContext : DbContext
        {
            var identityBuild = services.AddIdentityServices<TUser, TRole>(configuration);
            identityBuild.AddDefaultTokenProviders();
            
            if(!string.Equals(typeof(TDbContext).Name, "FakeDbContext", StringComparison.OrdinalIgnoreCase))
                identityBuild.AddEntityFrameworkStores<TDbContext>();
            
            var jwtSettings = new JwtSettings();
            configuration.Bind(nameof(jwtSettings), jwtSettings);
            if (string.IsNullOrEmpty(jwtSettings.Secret))
                throw new ArgumentOutOfRangeException("jwtSettings.Secret",
                    "Value cannot be null or empty; update configuration (AppSettings).");
            if (string.IsNullOrEmpty(jwtSettings.RefreshSecret))
                throw new ArgumentOutOfRangeException("jwtSettings.RefreshSecret",
                    "Value cannot be null or empty; update configuration (AppSettings).");
            if(jwtSettings.TokenLifetime == default)
                jwtSettings.TokenLifetime = TimeSpan.FromHours(1);

            services.AddHttpContextAccessor();
            
            services.AddSingleton(jwtSettings);
            services.AddSingleton(jwtSettings.EmailSettings);

            services.AddScoped<IEmailSender, BasicSendGridEmailSender>();

            services.AddScoped<JwtSecurityTokenHandler>();
            
            services.AddScoped<ITokenAppService<TUser>, TokenAppService<TUser, TRole>>();
            services.AddScoped<IIdentityAppService<TUser>, IdentityAppService<TUser, TRole>>();
            services.AddScoped<IClaimsBuilder<TUser, string>>(_ => claimsBuilder);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.Secret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = false,
                ValidateLifetime = true
            };
            
            services.AddSingleton(tokenValidationParameters);

            services.AddAuthentication(x =>
                {
                    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(x =>
                {
                    x.SaveToken = true;
                    x.TokenValidationParameters = tokenValidationParameters;
                });

            services.AddAuthorization();
            
            return services;
        }
        
        public static IServiceCollection AddSneddoJwtAuth<TUser, TRole>(this IServiceCollection services, IConfiguration configuration) 
            where TUser : IdentityUser
            where TRole : IdentityRole
        {
            Func<TUser, string, List<Claim>> emptyBuilder = delegate(TUser user, string companyId) { return new List<Claim>(); };
            return services.AddSneddoJwtAuth<TUser, TRole, FakeDbContext>(configuration,new ClaimsBuilder<TUser, string>
            {
                builder = emptyBuilder
            });
        }

        private static IdentityBuilder AddIdentityServices<TUser, TRole>(this IServiceCollection services, IConfiguration configuration)
            where TUser : IdentityUser
            where TRole : IdentityRole
        {
            return services.AddIdentity<TUser, TRole>(opt =>
            {
                opt.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider;
                opt.ClaimsIdentity.UserIdClaimType = "id";
                opt.Password.RequireNonAlphanumeric =
                    configuration.GetValue<bool>("IdentityOptions:Password:RequireNonAlphanumeric");
            });
        }
    }
}