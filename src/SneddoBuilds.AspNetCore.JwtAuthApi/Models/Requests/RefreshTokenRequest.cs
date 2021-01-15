namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Requests
{
    public class RefreshTokenRequest
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }
    }
}