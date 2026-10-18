using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.TwoFactor.Totp;

/// <summary>
/// TOTP (RFC 6238) over HMAC-SHA1, HMAC-SHA256 or HMAC-SHA512, implemented directly on the
/// platform HMAC primitives; no third-party code. The defaults are 6 digits, SHA1 and 30 s steps.
/// </summary>
public class TotpService
{
    /// <summary>Length in bytes of generated secrets (160 bits, the RFC 4226 recommendation), for every algorithm.</summary>
    public const int SecretLength = 20;

    /// <summary>Default step length in seconds.</summary>
    public const int StepSeconds = 30;

    /// <summary>Default number of digits in a code.</summary>
    public const int Digits = 6;

    /// <summary>Accepted drift in steps, in each direction.</summary>
    public const int WindowSteps = 1;

    /// <summary>
    /// Generates a new random secret.
    /// </summary>
    /// <returns>The secret bytes.</returns>
    public static byte[] GenerateSecret() => RandomNumberGenerator.GetBytes(SecretLength);

    /// <summary>
    /// Gets the time-step counter for an instant.
    /// </summary>
    /// <param name="time">The instant.</param>
    /// <param name="periodSeconds">The step length in seconds.</param>
    /// <returns>The counter (Unix time divided by the step).</returns>
    public static long GetCounter(DateTimeOffset time, int periodSeconds = StepSeconds) => time.ToUnixTimeSeconds() / periodSeconds;

    /// <summary>
    /// Computes the code for a counter (RFC 4226 dynamic truncation).
    /// </summary>
    /// <param name="secret">The shared secret.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="digits">The number of digits.</param>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <returns>The zero-padded code.</returns>
    public static string ComputeCode(byte[] secret, long counter, int digits = Digits, TotpAlgorithm algorithm = TotpAlgorithm.Sha1)
    {
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, counter);
        Span<byte> hash = stackalloc byte[64];
        int length = algorithm switch
        {
            TotpAlgorithm.Sha1 => HMACSHA1.HashData(secret, message, hash),
            TotpAlgorithm.Sha256 => HMACSHA256.HashData(secret, message, hash),
            TotpAlgorithm.Sha512 => HMACSHA512.HashData(secret, message, hash),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        int offset = hash[length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        int modulus = 1;
        for (int i = 0; i < digits; i++)
        {
            modulus *= 10;
        }

        return (binary % modulus).ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    /// <summary>
    /// Checks a code with the default options (6 digits, SHA1, 30 s).
    /// </summary>
    /// <param name="secret">The shared secret.</param>
    /// <param name="code">The code typed by the user (spaces are ignored).</param>
    /// <param name="now">The current time.</param>
    /// <param name="lastAcceptedCounter">The last counter accepted for this user, or -1 if none.</param>
    /// <param name="matchedCounter">The counter the code matched, if valid.</param>
    /// <returns><c>true</c> if valid and fresh.</returns>
    public static bool TryValidate(byte[] secret, string? code, DateTimeOffset now, long lastAcceptedCounter, out long matchedCounter)
        => TryValidate(secret, code, now, lastAcceptedCounter, TotpOptions.Default, out matchedCounter);

    /// <summary>
    /// Checks a code against the window around <paramref name="now"/>, rejecting replays.
    /// </summary>
    /// <param name="secret">The shared secret.</param>
    /// <param name="code">The code typed by the user (spaces are ignored).</param>
    /// <param name="now">The current time.</param>
    /// <param name="lastAcceptedCounter">The last counter accepted for this user, or -1 if none.</param>
    /// <param name="options">Digits, algorithm and period the secret was enrolled with.</param>
    /// <param name="matchedCounter">The counter the code matched, if valid.</param>
    /// <returns><c>true</c> if the code is valid and its counter is greater than <paramref name="lastAcceptedCounter"/>.</returns>
    public static bool TryValidate(byte[] secret, string? code, DateTimeOffset now, long lastAcceptedCounter, TotpOptions options, out long matchedCounter)
    {
        matchedCounter = -1;
        if (code is null || !options.IsValid)
        {
            return false;
        }

        var normalized = code.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (normalized.Length != options.Digits)
        {
            return false;
        }

        var candidate = Encoding.ASCII.GetBytes(normalized);
        var current = GetCounter(now, options.PeriodSeconds);
        bool found = false;

        // Every step in the window is always evaluated, with a constant-time comparison,
        // so timing does not reveal which step (if any) matched.
        for (long counter = current - WindowSteps; counter <= current + WindowSteps; counter++)
        {
            var expected = Encoding.ASCII.GetBytes(ComputeCode(secret, counter, options.Digits, options.Algorithm));
            bool equal = CryptographicOperations.FixedTimeEquals(expected, candidate);
            if (equal && counter > lastAcceptedCounter && counter > matchedCounter)
            {
                matchedCounter = counter;
                found = true;
            }
        }

        return found;
    }

    /// <summary>
    /// Builds the otpauth:// URI that authenticator apps read from a QR code.
    /// </summary>
    /// <param name="issuer">The issuer name.</param>
    /// <param name="account">The account name (user name).</param>
    /// <param name="secret">The shared secret.</param>
    /// <param name="options">Digits, algorithm and period; defaults if <c>null</c>.</param>
    /// <returns>The URI.</returns>
    public static string BuildOtpAuthUri(string issuer, string account, byte[] secret, TotpOptions? options = null)
    {
        options ??= TotpOptions.Default;
        var label = Uri.EscapeDataString(issuer) + ":" + Uri.EscapeDataString(account);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"otpauth://totp/{label}?secret={Base32.Encode(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm={options.AlgorithmName}&digits={options.Digits}&period={options.PeriodSeconds}");
    }
}
