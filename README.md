# SneddoBuilds.AspNetCore.JwtAuthApi

Quickly add JWT authentication to your webapi project, extending the out of the box asp.net core Identity functionality.

## Get started in 5 steps

1. Install the nuget package
  `Install-package SneddoBuilds.AspNetCore.JwtAuthApi`
2. Add required configuration to appsettings

``"JwtSettings": {
    "Secret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "RefreshSecret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "TokenLifetime": "01:00:00",
    "EmailSettings" : 
    {
      "FromEmail" : "test@test.com",
      "FromName" : "tester name",
      "ForgotPasswordSubject": "Update your password",
      "ForgotPasswordBody" : "Please use this code to reset your password: {{token}}"
    }``
    
3. Add service reference to `AddSneddoJwtAuth<TUser,TRole>(configuration);` in `startup.cs`
4. Add the security into Swagger Gen
5. Add a new controller and inherit from AuthControllerBase. Add attributes for routing and auth.

Done. 

## Example
See the example web app here: 
