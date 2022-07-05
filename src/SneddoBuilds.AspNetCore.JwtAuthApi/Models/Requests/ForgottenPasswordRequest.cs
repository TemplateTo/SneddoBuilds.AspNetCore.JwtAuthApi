namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Requests
{
    public class ForgottenPasswordRequest
    {
        public string Email { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
    }
}