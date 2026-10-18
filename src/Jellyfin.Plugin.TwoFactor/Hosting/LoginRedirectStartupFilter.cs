using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace Jellyfin.Plugin.TwoFactor.Hosting;

/// <summary>
/// Puts <see cref="PasswordLoginGuardMiddleware"/> and <see cref="WebIndexMiddleware"/> at the start of the server request pipeline.
/// Plugins cannot add middleware directly; the host runs every registered <see cref="IStartupFilter"/>.
/// </summary>
public sealed class LoginRedirectStartupFilter : IStartupFilter
{
    /// <inheritdoc />
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.UseMiddleware<PasswordLoginGuardMiddleware>();
            app.UseMiddleware<WebIndexMiddleware>();
            next(app);
        };
    }
}
