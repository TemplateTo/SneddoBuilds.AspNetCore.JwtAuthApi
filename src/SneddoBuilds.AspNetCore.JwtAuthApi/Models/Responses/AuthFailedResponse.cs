using System.Collections.Generic;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses
{
    public class AuthFailedResponse
    {
        public IEnumerable<string> Errors { get; set; }
    }
}