
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using GUVENYOLDAS.JWT;

class Program
{
    static void Main()
    {
        // some info I want to keep in token
        string userId = "123456789";
        DateTime expires = DateTime.UtcNow.AddHours(1);

        // JWT create
        string token = JwtHelper.GenerateJwt(userId, expires);

        var jwtObject = JwtHelper.DeserializeJwt(token);

        Console.WriteLine("Created JWT: " + token);

    }

    
}