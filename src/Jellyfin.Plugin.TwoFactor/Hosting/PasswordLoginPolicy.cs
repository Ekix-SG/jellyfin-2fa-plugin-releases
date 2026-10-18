using System;

namespace Jellyfin.Plugin.TwoFactor.Hosting;

/// <summary>
/// Whether password-only logins through Jellyfin's own endpoints are allowed.
/// They are blocked by default, because they would let anyone who knows a password skip the second factor.
/// </summary>
/// <param name="Allowed"><c>true</c> if the emergency variable turned the block off.</param>
public sealed record PasswordLoginPolicy(bool Allowed)
{
    /// <summary>Environment variable that turns the block off. For emergencies only.</summary>
    public const string AllowVariable = "TWOFACTOR_ALLOW_PASSWORD_LOGIN";

    /// <summary>
    /// Reads the policy from the environment. Unset or empty means blocked. <c>true</c>/<c>1</c> allows,
    /// <c>false</c>/<c>0</c> blocks, anything else is an error and the block stays on (fail closed).
    /// </summary>
    /// <param name="getVariable">Returns the value of an environment variable, or <c>null</c>.</param>
    /// <param name="error">An error message (the value is not included), or <c>null</c>.</param>
    /// <returns>The policy.</returns>
    public static PasswordLoginPolicy FromEnvironment(Func<string, string?> getVariable, out string? error)
    {
        error = null;
        var text = getVariable(AllowVariable)?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return new PasswordLoginPolicy(false);
        }

        if (text.Equals("true", StringComparison.OrdinalIgnoreCase) || text == "1")
        {
            return new PasswordLoginPolicy(true);
        }

        if (text.Equals("false", StringComparison.OrdinalIgnoreCase) || text == "0")
        {
            return new PasswordLoginPolicy(false);
        }

        error = $"{AllowVariable} must be true, false, 1 or 0. Password-only logins stay blocked.";
        return new PasswordLoginPolicy(false);
    }
}
