using System;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Jellyfin.Plugin.TwoFactor.Api;

/// <summary>
/// Turns every request the model binder could not accept (empty body, text that is not JSON, wrong types)
/// into the same uniform 401 as a failed login, so that no response differs by the kind of mistake.
/// The controller must not be marked <c>[ApiController]</c>, because that attribute would answer 400 first.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class UniformErrorFilterAttribute : ActionFilterAttribute
{
    /// <inheritdoc />
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        if (!context.ModelState.IsValid || context.ActionArguments.Values.Any(value => value is null))
        {
            context.Result = new UnauthorizedObjectResult(new ErrorResponse());
        }
    }
}
