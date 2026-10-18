namespace Jellyfin.Plugin.TwoFactor.Totp;

/// <summary>
/// The options new enrollments use, read once from the environment at start-up.
/// Entries that already exist keep the options they were enrolled with.
/// </summary>
/// <param name="Options">The options (defaults if some variable was invalid).</param>
/// <param name="IsValid"><c>false</c> if any TOTP variable was set to an invalid value; logins are refused then.</param>
public sealed record TotpSettings(TotpOptions Options, bool IsValid);
