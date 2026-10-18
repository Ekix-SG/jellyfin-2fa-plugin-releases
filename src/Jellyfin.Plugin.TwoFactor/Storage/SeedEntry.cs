using System;
using System.Text.Json.Serialization;
using Jellyfin.Plugin.TwoFactor.Totp;

namespace Jellyfin.Plugin.TwoFactor.Storage;

/// <summary>
/// A stored TOTP seed for one user.
/// </summary>
public class SeedEntry
{
    /// <summary>Gets or sets the Jellyfin user id.</summary>
    [JsonPropertyName("userId")]
    public Guid UserId { get; set; }

    /// <summary>Gets or sets the secret, Base32 encoded. The whole entry is encrypted before it is written to disk.</summary>
    [JsonPropertyName("secret")]
    public string Secret { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether the user confirmed a first code.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the digits per code the secret was enrolled with.</summary>
    [JsonPropertyName("digits")]
    public int Digits { get; set; } = 6;

    /// <summary>Gets or sets the HMAC algorithm name (SHA1, SHA256 or SHA512) the secret was enrolled with.</summary>
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "SHA1";

    /// <summary>Gets or sets the step length in seconds the secret was enrolled with.</summary>
    [JsonPropertyName("period")]
    public int PeriodSeconds { get; set; } = 30;

    /// <summary>Gets or sets the last accepted time-step counter (anti-replay), -1 if none.</summary>
    [JsonPropertyName("lastCounter")]
    public long LastCounter { get; set; } = -1;

    /// <summary>
    /// Gets the TOTP parameters stored with this entry. Entries written by earlier builds have none and
    /// get the defaults (6 digits, SHA1, 30 s), which is what they were enrolled with.
    /// </summary>
    /// <returns>The options, or <c>null</c> if the stored values are not valid.</returns>
    public TotpOptions? GetOptions()
    {
        if (!TotpOptions.TryParseAlgorithm(Algorithm, out var algorithm))
        {
            return null;
        }

        var options = new TotpOptions(Digits, algorithm, PeriodSeconds);
        return options.IsValid ? options : null;
    }
}
