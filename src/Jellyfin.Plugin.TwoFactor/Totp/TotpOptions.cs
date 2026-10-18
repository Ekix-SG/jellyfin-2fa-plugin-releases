using System;
using System.Collections.Generic;
using System.Globalization;

namespace Jellyfin.Plugin.TwoFactor.Totp;

/// <summary>
/// HMAC algorithm used to compute codes (RFC 6238 section 1.2).
/// </summary>
public enum TotpAlgorithm
{
    /// <summary>HMAC-SHA1 (default; what every authenticator app supports).</summary>
    Sha1,

    /// <summary>HMAC-SHA256.</summary>
    Sha256,

    /// <summary>HMAC-SHA512.</summary>
    Sha512
}

/// <summary>
/// The three TOTP parameters that an <c>otpauth://</c> URI carries: digits, algorithm and period.
/// </summary>
/// <param name="Digits">Digits per code, 6 to 8.</param>
/// <param name="Algorithm">The HMAC algorithm.</param>
/// <param name="PeriodSeconds">Seconds each code lasts (the time step), 15 to 300.</param>
public sealed record TotpOptions(int Digits, TotpAlgorithm Algorithm, int PeriodSeconds)
{
    /// <summary>Environment variable for <see cref="Digits"/>.</summary>
    public const string DigitsVariable = "TWOFACTOR_DIGITS";

    /// <summary>Environment variable for <see cref="Algorithm"/>.</summary>
    public const string AlgorithmVariable = "TWOFACTOR_ALGORITHM";

    /// <summary>Environment variable for <see cref="PeriodSeconds"/>.</summary>
    public const string PeriodVariable = "TWOFACTOR_PERIOD_SECONDS";

    /// <summary>Gets the smallest accepted digit count.</summary>
    public const int MinDigits = 6;

    /// <summary>Gets the largest accepted digit count.</summary>
    public const int MaxDigits = 8;

    /// <summary>Gets the smallest accepted period.</summary>
    public const int MinPeriod = 15;

    /// <summary>Gets the largest accepted period.</summary>
    public const int MaxPeriod = 300;

    /// <summary>Gets the defaults: 6 digits, SHA1, 30 seconds (what Google Authenticator uses).</summary>
    public static TotpOptions Default { get; } = new(6, TotpAlgorithm.Sha1, 30);

    /// <summary>Gets the algorithm name as written in the otpauth URI.</summary>
    public string AlgorithmName => Algorithm switch
    {
        TotpAlgorithm.Sha1 => "SHA1",
        TotpAlgorithm.Sha256 => "SHA256",
        TotpAlgorithm.Sha512 => "SHA512",
        _ => throw new InvalidOperationException("Unknown algorithm.")
    };

    /// <summary>
    /// Gets a value indicating whether the values are inside the accepted ranges.
    /// </summary>
    public bool IsValid => Digits is >= MinDigits and <= MaxDigits
        && Enum.IsDefined(Algorithm)
        && PeriodSeconds is >= MinPeriod and <= MaxPeriod;

    /// <summary>
    /// Parses an algorithm name (SHA1, SHA256 or SHA512, any case).
    /// </summary>
    /// <param name="text">The name.</param>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns><c>true</c> if recognized.</returns>
    public static bool TryParseAlgorithm(string? text, out TotpAlgorithm algorithm)
    {
        switch (text?.Trim().ToUpperInvariant())
        {
            case "SHA1":
                algorithm = TotpAlgorithm.Sha1;
                return true;
            case "SHA256":
                algorithm = TotpAlgorithm.Sha256;
                return true;
            case "SHA512":
                algorithm = TotpAlgorithm.Sha512;
                return true;
            default:
                algorithm = TotpAlgorithm.Sha1;
                return false;
        }
    }

    /// <summary>
    /// Reads the options from environment variables. A variable that is unset or empty keeps its default;
    /// a variable that is set to something invalid is an error (the values are never silently replaced).
    /// </summary>
    /// <param name="getVariable">Returns the value of an environment variable, or <c>null</c>.</param>
    /// <param name="options">The options (defaults for anything unset; meaningless if there are errors).</param>
    /// <param name="errors">One message per invalid variable. Values are not included.</param>
    /// <returns><c>true</c> if there were no errors.</returns>
    public static bool TryFromEnvironment(Func<string, string?> getVariable, out TotpOptions options, out IReadOnlyList<string> errors)
    {
        var problems = new List<string>();
        var digits = Default.Digits;
        var algorithm = Default.Algorithm;
        var period = Default.PeriodSeconds;

        var digitsText = getVariable(DigitsVariable)?.Trim();
        if (!string.IsNullOrEmpty(digitsText)
            && !(int.TryParse(digitsText, NumberStyles.None, CultureInfo.InvariantCulture, out digits) && digits is >= MinDigits and <= MaxDigits))
        {
            problems.Add($"{DigitsVariable} must be an integer from {MinDigits} to {MaxDigits}.");
        }

        var algorithmText = getVariable(AlgorithmVariable)?.Trim();
        if (!string.IsNullOrEmpty(algorithmText) && !TryParseAlgorithm(algorithmText, out algorithm))
        {
            problems.Add($"{AlgorithmVariable} must be SHA1, SHA256 or SHA512.");
        }

        var periodText = getVariable(PeriodVariable)?.Trim();
        if (!string.IsNullOrEmpty(periodText)
            && !(int.TryParse(periodText, NumberStyles.None, CultureInfo.InvariantCulture, out period) && period is >= MinPeriod and <= MaxPeriod))
        {
            problems.Add($"{PeriodVariable} must be an integer number of seconds from {MinPeriod} to {MaxPeriod}.");
        }

        errors = problems;
        options = problems.Count == 0 ? new TotpOptions(digits, algorithm, period) : Default;
        return problems.Count == 0;
    }
}
