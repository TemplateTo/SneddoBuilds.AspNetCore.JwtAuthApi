using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Models.Requests
{
    public class UserRegistrationRequest
    {
        [EmailAddress]
        public string Email { get; set; }
        [MaxLength(54)]
        public string Password { get; set; }
        
        public List<UserParameter> UserParameters { get; set; }
    }

    public class UserParameter
    {
        public string Name { get; set; }
        public string Value { get; set; }
    }

}