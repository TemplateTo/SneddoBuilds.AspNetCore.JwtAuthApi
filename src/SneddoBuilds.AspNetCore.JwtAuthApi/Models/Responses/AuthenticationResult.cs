using System.Collections.Generic;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses
{
    public class AuthenticationResult
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }

        public bool Success { get; set; }

        public IEnumerable<string> Errors { get; set; }
    }

    public class RegisterResult<TUser>
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }

        public bool Success { get; set; }

        public IEnumerable<string> Errors { get; set; }
        
        public TUser User { get; set; }
    }
}