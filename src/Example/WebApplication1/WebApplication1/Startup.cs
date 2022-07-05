using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using SneddoBuilds.AspNetCore.JwtAuthApi.Extensions;
using WebApplication1.Data;

namespace WebApplication1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<DefaultDataContext>(options =>
                options.UseSqlite(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddControllers();
            
            services.AddCors(o => o.AddPolicy("AllowAll", builder =>
            {
                builder.SetIsOriginAllowed(_ => true)
                    .AllowAnyMethod()
                    .AllowCredentials()
                    .AllowAnyHeader();
            }));
            
            //TODO: 01 -- Add configuration to appsettings (go look at file)
            //TODO: 02 -- Add service reference to AddSneddoJwtAuth<TUser,TRole>(configuration);
            services.AddSneddoJwtAuth<IdentityUser,IdentityRole, DefaultDataContext>(Configuration);
			
			//Install package NSwag.AspNetCore
			services.AddOpenApiDocument();
            
			services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo {Title = "WebApplication1", Version = "v1"});
                //TODO: 03 -- Add the security into Swagger
                c.SetupJwtSecurity();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseOpenApi();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApplication1 v1"));
            }
            app.UseHttpsRedirection();

            app.UseCors("AllowAll");
            
            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });

            //await SeedUser(app);
        }
        
        private static async Task SeedUser(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices
                .GetRequiredService<IServiceScopeFactory>()
                .CreateScope())
            {
                using (var context = serviceScope.ServiceProvider.GetService<DefaultDataContext>())
                {
                    using (var userManager = serviceScope.ServiceProvider.GetService<UserManager<IdentityUser>>())
                    {
                        if (!userManager.Users.Any(x => x.UserName == "test@test.com"))
                        {
                            var user = new IdentityUser
                            {
                                Email = "test@test.com",
                                UserName = "test@test.com",
                                NormalizedEmail = "test@test.com",
                                EmailConfirmed = true,
                                LockoutEnabled = false,
                                SecurityStamp = Guid.NewGuid().ToString()
                            };
                            await userManager.CreateAsync(user, "5n3dd0Bu!ld5");
                        }
                    }
                    await context.SaveChangesAsync();
                }
            }
        }
    }
}