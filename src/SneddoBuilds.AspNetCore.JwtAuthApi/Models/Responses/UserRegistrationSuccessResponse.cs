namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Responses
{
    public class UserRegistrationSuccessResponse<TUser> : AuthSuccessResponse
    {
        public TUser User { get; set; }
    }
}