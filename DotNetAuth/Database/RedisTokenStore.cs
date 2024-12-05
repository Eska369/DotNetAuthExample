using StackExchange.Redis;

namespace DotNetAuth.Database;

public class RedisTokenStore
{
    private readonly IConnectionMultiplexer _redis;

    public RedisTokenStore(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }
    public async Task StoreTokenAsync(string token, DateTime expiration)
    {
        var db = _redis.GetDatabase();
        await db.StringSetAsync(token, "active", expiration - DateTime.UtcNow);
    }

    public async Task<bool> IsTokenActiveAsync(string token)
    {
        var db = _redis.GetDatabase();
        var value = await db.StringGetAsync(token);
        return value == "active";
    }

    public async Task RevokeTokenAsync(string token)
    {
        var db = _redis.GetDatabase();
        await db.StringSetAsync(token, "revoked");
    }
}