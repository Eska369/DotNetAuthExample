using DotNetAuth.Database;

namespace DotNetAuth.Middleware;

public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IServiceProvider _serviceProvider;

    public TokenValidationMiddleware(RequestDelegate next, IServiceProvider serviceProvider)
    {
        _next = next;
        _serviceProvider = serviceProvider;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers.Authorization.ToString().Replace("Bearer ", "");

        if (!string.IsNullOrEmpty(token))
        {
            using var scope = _serviceProvider.CreateScope();
            var tokenStore = scope.ServiceProvider.GetRequiredService<RedisTokenStore>();

            var isActive = await tokenStore.IsTokenActiveAsync(token);
            if (!isActive)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Token is revoked.");
                return;
            }
        }

        await _next(context);
    }
}