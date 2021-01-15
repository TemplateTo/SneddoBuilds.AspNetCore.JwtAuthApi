namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models
{
    public class EmailSettings
    {
        public string FromEmail { get; set; }
        public string FromName { get; set; }
        public string ForgotPasswordSubject { get; set; }
        //{{Token}} can be used within the body text. Will be replaced with the reset token before sending
        public string ForgotPasswordBody { get; set; }
    }
}