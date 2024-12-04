using DotNetAuth.Database;
using DotNetAuth.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotNetAuth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class OAuthClientsController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public OAuthClientsController(ApplicationDbContext context)
    {
        _context = context;
    }

    [HttpPost]
    public async Task<IActionResult> CreateClient([FromBody] CreateOAuthClientModel model)
    {
        var client = new OAuthClient
        {
            Name = model.Name,
            ClientId = Guid.NewGuid().ToString(),
            ClientSecret = Guid.NewGuid().ToString(),
            AllowedScopes = model.AllowedScopes
        };

        _context.OAuthClients.Add(client);
        await _context.SaveChangesAsync();

        return Ok(new { client.ClientId, client.ClientSecret });
    }
}

public class CreateOAuthClientModel
{
    public string Name { get; set; }
    public string[] AllowedScopes { get; set; }
}