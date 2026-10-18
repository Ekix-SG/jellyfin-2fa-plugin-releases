using System;

namespace Jellyfin.Plugin.TwoFactor.Storage;

/// <summary>A freshly generated invitation code. The plain code exists only in this object: the store keeps a hash.</summary>
/// <param name="InviteId">The id of the invitation (not secret; goes into the ticket once the code is accepted).</param>
/// <param name="Code">The plain code, to be shown once.</param>
/// <param name="ExpiresAt">When the code stops being valid.</param>
public sealed record InviteIssued(Guid InviteId, string Code, DateTimeOffset ExpiresAt);

/// <summary>What is known about a live invitation (never the code).</summary>
/// <param name="InviteId">The id of the invitation.</param>
/// <param name="ExpiresAt">When the code stops being valid.</param>
public sealed record InviteInfo(Guid InviteId, DateTimeOffset ExpiresAt);

/// <summary>
/// Persistent store of single-use invitation codes that allow a user to enroll an authenticator.
/// A code is tied to one user; a user has at most one live code.
/// </summary>
public interface IInviteStore
{
    /// <summary>
    /// Gets a value indicating whether codes can be stored (a valid encryption key is configured).
    /// When <c>false</c>, every other member throws <see cref="InvalidOperationException"/>.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Generates a code for a user. Any code the user had before stops being valid.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="ttl">How long the code lasts.</param>
    /// <returns>The plain code and its metadata.</returns>
    InviteIssued Create(Guid userId, TimeSpan ttl);

    /// <summary>
    /// Checks a code (constant-time comparison) without using it up.
    /// </summary>
    /// <param name="userId">The user the code must belong to.</param>
    /// <param name="code">The code typed by the user (case, spaces and hyphens are ignored).</param>
    /// <returns>The invitation id, or <c>null</c> if there is no live, matching code for that user.</returns>
    Guid? TryValidate(Guid userId, string? code);

    /// <summary>
    /// Gets a value indicating whether the invitation is still live.
    /// </summary>
    /// <param name="inviteId">The invitation id returned by <see cref="TryValidate"/>.</param>
    /// <returns><c>true</c> if it exists, has not expired and has not been invalidated.</returns>
    bool IsActive(Guid inviteId);

    /// <summary>
    /// Uses the invitation up. Only one caller can succeed.
    /// </summary>
    /// <param name="inviteId">The invitation id.</param>
    /// <returns><c>true</c> if this call consumed it.</returns>
    bool Consume(Guid inviteId);

    /// <summary>
    /// Deletes the user's live code, if any.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <returns><c>true</c> if there was one.</returns>
    bool Revoke(Guid userId);

    /// <summary>
    /// Counts a wrong code against the user's live invitation, which is invalidated at <see cref="FileInviteStore.MaxFailedAttempts"/>.
    /// Does nothing if the user has none.
    /// </summary>
    /// <param name="userId">The user id.</param>
    void RegisterFailure(Guid userId);

    /// <summary>
    /// Gets the user's live invitation.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <returns>Its metadata, or <c>null</c>.</returns>
    InviteInfo? GetActive(Guid userId);
}
