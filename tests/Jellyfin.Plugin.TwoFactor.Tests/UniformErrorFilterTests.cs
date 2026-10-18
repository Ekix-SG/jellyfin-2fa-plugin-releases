using Jellyfin.Plugin.TwoFactor.Api;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class UniformErrorFilterTests
{
    private static ActionExecutingContext Build(Dictionary<string, object?> arguments, bool validModel)
    {
        var actionContext = new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor());
        if (!validModel)
        {
            actionContext.ModelState.AddModelError(string.Empty, "A non-empty request body is required.");
        }

        return new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), arguments, new object());
    }

    private static void AssertUniform(ActionExecutingContext context)
    {
        var result = Assert.IsType<UnauthorizedObjectResult>(context.Result);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal(new ErrorResponse().Error, Assert.IsType<ErrorResponse>(result.Value).Error);
    }

    [Fact]
    public void InvalidModelStateGivesUniform401()
    {
        var context = Build(new() { ["request"] = new Step1Request() }, validModel: false);
        new UniformErrorFilterAttribute().OnActionExecuting(context);
        AssertUniform(context);
    }

    [Fact]
    public void NullBodyGivesUniform401()
    {
        var context = Build(new() { ["request"] = null }, validModel: true);
        new UniformErrorFilterAttribute().OnActionExecuting(context);
        AssertUniform(context);
    }

    [Fact]
    public void ValidRequestPassesThrough()
    {
        var context = Build(new() { ["request"] = new Step1Request() }, validModel: true);
        new UniformErrorFilterAttribute().OnActionExecuting(context);
        Assert.Null(context.Result);
    }
}
