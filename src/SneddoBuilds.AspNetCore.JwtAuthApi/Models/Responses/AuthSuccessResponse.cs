namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses
{
    public class AuthSuccessResponse
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }
    }
}