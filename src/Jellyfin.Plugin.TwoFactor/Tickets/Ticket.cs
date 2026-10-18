using System;

namespace Jellyfin.Plugin.TwoFactor.Tickets;

/// <summary>
/// A short-lived, single-use proof that the password step succeeded.
/// It can only be used to present a TOTP code; it never opens a session by itself.
/// </summary>
public sealed class Ticket
{
    /// <summary>Gets the user id.</summary>
    public required Guid UserId { get; init; }

    /// <summary>Gets the user name (used as the authenticator account label).</summary>
    public required string Username { get; init; }

    /// <summary>Gets the client IP the ticket is bound to.</summary>
    public required string RemoteIp { get; init; }

    /// <summary>Gets the device id the ticket is bound to.</summary>
    public required string DeviceId { get; init; }

    /// <summary>Gets the device name sent by the client.</summary>
    public required string DeviceName { get; init; }

    /// <summary>Gets a value indicating whether the user still has to enroll an authenticator.</summary>
    public required bool NeedsEnrollment { get; init; }

    /// <summary>
    /// Gets a value indicating whether the ticket belongs to a seed rotation by a signed-in user.
    /// Such a ticket is useless for the login endpoints.
    /// </summary>
    public bool IsRotation { get; init; }

    /// <summary>Gets the expiry instant.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Gets or sets the number of failed code attempts.</summary>
    public int FailedAttempts { get; set; }

    /// <summary>Gets or sets the secret generated during enrollment, not persisted until confirmed.</summary>
    public byte[]? PendingSecret { get; set; }

    /// <summary>
    /// Gets or sets the id of the invitation code accepted by enrollment begin. Set by the server only; the
    /// confirm step never reads it from the client.
    /// </summary>
    public Guid? InviteId { get; set; }
}
