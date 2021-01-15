using System;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models
{
    public class JwtSettings
    {
        public string Secret { get; set; }
        
        public string RefreshSecret { get; set; }
        
        public TimeSpan TokenLifetime { get; set; }

        public EmailSettings EmailSettings { get; set; }
    }
}