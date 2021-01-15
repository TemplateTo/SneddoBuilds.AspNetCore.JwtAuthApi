namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Requests
{
    public class ResetPasswordRequest
    {
        public string ResetToken { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}