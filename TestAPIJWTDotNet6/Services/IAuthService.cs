using TestAPIJWTDotNet6.Models;

namespace TestAPIJWTDotNet6.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsyn(RegisterModel registerModel);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
