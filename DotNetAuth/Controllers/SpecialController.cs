using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotNetAuth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SpecialController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "MySpecialScope")]
    public IActionResult GetSpecialData()
    {
        return Ok("This is special data accessible only with the 'my.special.scope' scope.");
    }
}