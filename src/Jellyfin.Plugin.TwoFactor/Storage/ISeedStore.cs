using System;
using Jellyfin.Plugin.TwoFactor.Totp;

namespace Jellyfin.Plugin.TwoFactor.Storage;

/// <summary>
/// Persistent store of TOTP seeds.
/// </summary>
public interface ISeedStore
{
    /// <summary>
    /// Gets a value indicating whether seeds can be read and written (a valid encryption key is configured).
    /// When <c>false</c>, every other member throws <see cref="InvalidOperationException"/>.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Gets a value indicating whether the user has TOTP enabled (including an entry that cannot be decrypted).
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <returns><c>true</c> if enabled.</returns>
    bool IsEnabled(Guid userId);

    /// <summary>
    /// Stores an enabled seed for a user who has none yet.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="secret">The secret bytes.</param>
    /// <param name="acceptedCounter">The counter of the confirmation code, so it cannot be replayed.</param>
    /// <param name="options">Digits, algorithm and period the secret was enrolled with; stored with the entry.</param>
    /// <returns><c>false</c> if the user already has an entry (nothing is changed).</returns>
    bool TryEnroll(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options);

    /// <summary>
    /// Atomically validates a code for the user and records its counter so it cannot be used again.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="code">The code typed by the user.</param>
    /// <param name="now">The current time.</param>
    /// <returns><c>true</c> if the code is valid and fresh.</returns>
    bool TryAcceptCode(Guid userId, string? code, DateTimeOffset now);

    /// <summary>
    /// Replaces the seed of a user who already has one enabled (rotation). The old seed stays valid until this call succeeds.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="secret">The new secret bytes.</param>
    /// <param name="acceptedCounter">The counter of the confirmation code made with the new secret, so it cannot be replayed.</param>
    /// <param name="options">Digits, algorithm and period of the new secret.</param>
    /// <returns><c>false</c> if the user has no enabled, readable entry (nothing is changed).</returns>
    bool TryReplace(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options);

    /// <summary>
    /// Deletes the entry of a user (administrator reset), including one that cannot be decrypted.
    /// The user enrolls again at the next login.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <returns><c>true</c> if there was an entry.</returns>
    bool Remove(Guid userId);
}
