using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Jellyfin.Plugin.TwoFactor.Tickets;

/// <summary>
/// In-memory store of tickets. Tickets are single use, expire after <see cref="Lifetime"/>,
/// are bound to user + IP + device id, and die after <see cref="MaxFailedAttempts"/> wrong codes.
/// </summary>
public class TicketStore
{
    /// <summary>Maximum wrong codes per ticket.</summary>
    public const int MaxFailedAttempts = 5;

    private const int MaxLiveTickets = 1000;

    private readonly object _lock = new();
    private readonly Dictionary<string, Ticket> _tickets = new();
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="TicketStore"/> class.
    /// </summary>
    /// <param name="time">The clock.</param>
    public TicketStore(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>
    /// Gets the ticket lifetime.
    /// </summary>
    public static TimeSpan Lifetime { get; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Issues a ticket.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="username">The user name.</param>
    /// <param name="remoteIp">The client IP.</param>
    /// <param name="deviceId">The device id.</param>
    /// <param name="deviceName">The device name.</param>
    /// <param name="needsEnrollment">Whether the user has to enroll.</param>
    /// <param name="isRotation">Whether the ticket is for a signed-in user's seed rotation (never for a login).</param>
    /// <returns>The opaque token (256 random bits) or <c>null</c> if the store is full.</returns>
    public string? Issue(Guid userId, string username, string remoteIp, string deviceId, string deviceName, bool needsEnrollment, bool isRotation = false)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            Purge(now);
            if (_tickets.Count >= MaxLiveTickets)
            {
                return null;
            }

            var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            _tickets[token] = new Ticket
            {
                UserId = userId,
                Username = username,
                RemoteIp = remoteIp,
                DeviceId = deviceId,
                DeviceName = deviceName,
                NeedsEnrollment = needsEnrollment,
                IsRotation = isRotation,
                ExpiresAt = now + Lifetime
            };
            return token;
        }
    }

    /// <summary>
    /// Looks up a ticket that is alive and bound to this IP and device. Does not consume it.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="remoteIp">The client IP.</param>
    /// <param name="deviceId">The device id.</param>
    /// <returns>The ticket, or <c>null</c>.</returns>
    public Ticket? Get(string? token, string remoteIp, string deviceId)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (!_tickets.TryGetValue(token, out var ticket))
            {
                return null;
            }

            if (ticket.ExpiresAt <= now)
            {
                _tickets.Remove(token);
                return null;
            }

            if (!string.Equals(ticket.RemoteIp, remoteIp, StringComparison.Ordinal)
                || !string.Equals(ticket.DeviceId, deviceId, StringComparison.Ordinal))
            {
                return null;
            }

            return ticket;
        }
    }

    /// <summary>
    /// Registers a wrong code. The ticket is destroyed once the limit is reached.
    /// </summary>
    /// <param name="token">The token.</param>
    public void RegisterFailure(string token)
    {
        lock (_lock)
        {
            if (_tickets.TryGetValue(token, out var ticket) && ++ticket.FailedAttempts >= MaxFailedAttempts)
            {
                _tickets.Remove(token);
            }
        }
    }

    /// <summary>
    /// Atomically removes the ticket. Only one caller can succeed.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <returns><c>true</c> if this call consumed it.</returns>
    public bool Consume(string token)
    {
        lock (_lock)
        {
            return _tickets.Remove(token);
        }
    }

    /// <summary>
    /// Returns the pending enrollment secret for a ticket, creating it on first use.
    /// </summary>
    /// <param name="ticket">The ticket.</param>
    /// <param name="generate">Generator for a new secret.</param>
    /// <returns>The pending secret.</returns>
    public byte[] GetOrCreatePendingSecret(Ticket ticket, Func<byte[]> generate)
    {
        lock (_lock)
        {
            return ticket.PendingSecret ??= generate();
        }
    }

    /// <summary>
    /// Records on the ticket the invitation code that enrollment begin accepted.
    /// </summary>
    /// <param name="ticket">The ticket.</param>
    /// <param name="inviteId">The invitation id.</param>
    public void AttachInvite(Ticket ticket, Guid inviteId)
    {
        lock (_lock)
        {
            ticket.InviteId = inviteId;
        }
    }

    private void Purge(DateTimeOffset now)
    {
        foreach (var key in _tickets.Where(t => t.Value.ExpiresAt <= now).Select(t => t.Key).ToList())
        {
            _tickets.Remove(key);
        }
    }
}
