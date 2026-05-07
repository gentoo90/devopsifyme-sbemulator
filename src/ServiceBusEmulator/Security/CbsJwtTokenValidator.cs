using Microsoft.IdentityModel.Tokens;
using ServiceBusEmulator.Abstractions.Security;
using System.IdentityModel.Tokens.Jwt;

namespace ServiceBusEmulator.Security
{
    internal class CbsJwtTokenValidator : ITokenValidator
    {
        public static CbsJwtTokenValidator Default { get; } = new();

        public void Validate(string token)
        {
            var validationParameters = new TokenValidationParameters
            {
                SignatureValidator = (t, _) => new JwtSecurityToken(t),
                ValidateIssuerSigningKey = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            var handler = new JwtSecurityTokenHandler();
            _ = handler.ValidateToken(token, validationParameters, out _);
        }
    }
}
