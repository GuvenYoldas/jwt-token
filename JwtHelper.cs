using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;


namespace GUVENYOLDAS.JWT
{
    public class JwtHelper
    {
        public const string secretKey = "hmacSha256-must-be-128-bit-or-more-hmacSha256-must-be-128-bit-or-more-hmacSha256-must-be-128-bit-or-more-hmacSha256-must-be-128-bit-or-more";
        public static string GenerateJwt(string userId, DateTime expires)
        {
            // content creating .. you can use your own object if you want. 
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expires).ToUnixTimeSeconds().ToString())
        };

            // master key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            // signing algorithm
            var algorithm = SecurityAlgorithms.HmacSha256;

            // creating
            var token = new JwtSecurityToken(
                claims: claims,
                expires: expires,
                signingCredentials: new SigningCredentials(key, algorithm)
            );

            // convert to string
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenString;
        }

        static bool ValidateJwt(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                // JWT key
                var key = Encoding.UTF8.GetBytes(secretKey);

                // JWT parameter check
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                };

                // JWT check
                SecurityToken validatedToken;
                tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static Claim[] DeserializeJwt(string token)
        {
            if (!ValidateJwt(token))
            {
                return null;
            }
            var tokenHandler = new JwtSecurityTokenHandler();

            // JWT token'ını parse etme
            var jwtToken = tokenHandler.ReadJwtToken(token);

            // JWT bilgilerini almak için JwtInfo sınıfını kullanarak deserialize işlemi
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, jwtToken.Payload["sub"].ToString()),
                new Claim(JwtRegisteredClaimNames.Jti,jwtToken.Payload["jti"].ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, jwtToken.Payload["iat"].ToString()),
                new Claim(JwtRegisteredClaimNames.Exp, jwtToken.Payload["exp"].ToString())
            };


            return claims;
        }
    }
}

