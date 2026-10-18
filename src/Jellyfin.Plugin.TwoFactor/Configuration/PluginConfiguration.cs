using System;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.TwoFactor.Configuration;

/// <summary>
/// Plugin configuration.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// Gets or sets the issuer name shown in the authenticator app.
    /// </summary>
    public string Issuer { get; set; } = "Jellyfin";

    /// <summary>
    /// Gets or sets how many hours an invitation code is valid (1 to 168; values outside are clamped).
    /// </summary>
    public int InviteTtlHours { get; set; } = 24;

    /// <summary>
    /// Gets the lifetime of a new invitation code.
    /// </summary>
    public TimeSpan InviteTtl => TimeSpan.FromHours(Math.Clamp(InviteTtlHours, 1, 168));
}
