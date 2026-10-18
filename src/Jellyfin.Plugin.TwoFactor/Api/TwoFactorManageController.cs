using System;
using System.IO;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Api;

/// <summary>
/// Endpoints that need a session: a user rotating their own authenticator, and an administrator resetting someone's.
/// Not marked <c>[ApiController]</c>, for the same reason as <see cref="TwoFactorController"/>.
/// </summary>
[Authorize]
[UniformErrorFilter]
[Route("TwoFactor")]
public class TwoFactorManageController : ControllerBase
{
    private const int MaxFieldLength = 256;

    // Claim that Jellyfin's authentication handler puts the user id in (InternalClaimTypes.UserId).
    private const string UserIdClaim = "Jellyfin-UserId";

    // Claim with the access token of the request (InternalClaimTypes.Token).
    private const string TokenClaim = "Jellyfin-Token";

    // Name of Jellyfin's administrator authorization policy (Policies.RequiresElevation).
    private const string ElevationPolicy = "RequiresElevation";

    private readonly IUserManager _userManager;
    private readonly ISeedStore _seeds;
    private readonly IInviteStore _invites;
    private readonly TotpSettings _totp;
    private readonly TicketStore _tickets;
    private readonly LoginThrottle _throttle;
    private readonly ISessionManager _sessionManager;
    private readonly TimeProvider _time;
    private readonly ILogger<TwoFactorManageController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TwoFactorManageController"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="seeds">The seed store.</param>
    /// <param name="invites">The invitation code store.</param>
    /// <param name="totp">The TOTP options for new seeds.</param>
    /// <param name="tickets">The ticket store.</param>
    /// <param name="throttle">The temporary block by IP and user name.</param>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="time">The clock.</param>
    /// <param name="logger">The logger.</param>
    public TwoFactorManageController(
        IUserManager userManager,
        ISeedStore seeds,
        IInviteStore invites,
        TotpSettings totp,
        TicketStore tickets,
        LoginThrottle throttle,
        ISessionManager sessionManager,
        TimeProvider time,
        ILogger<TwoFactorManageController> logger)
    {
        _userManager = userManager;
        _seeds = seeds;
        _invites = invites;
        _totp = totp;
        _tickets = tickets;
        _throttle = throttle;
        _sessionManager = sessionManager;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Rotation, part 1: checks the password again and generates the pending secret.
    /// The current seed stays valid until part 2 succeeds.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>A rotation ticket with the otpauth URI, or a uniform error.</returns>
    [HttpPost("Manage/Begin")]
    public async Task<ActionResult> ManageBegin([FromBody] ManageBeginRequest request)
    {
        var ip = GetIp();
        if (!_seeds.IsAvailable || !_totp.IsValid || !TryGetSessionUserId(out var userId) || _throttle.IsBlocked(ip, null)
            || request.Password is null || request.Password.Length > MaxFieldLength
            || string.IsNullOrWhiteSpace(request.DeviceId) || request.DeviceId.Length > MaxFieldLength)
        {
            return Fail();
        }

        try
        {
            var current = _userManager.GetUserById(userId);

            // Only users who already have an authenticator rotate; the others enroll at their next login.
            if (current is null || !_seeds.IsEnabled(userId))
            {
                return Fail();
            }

            var user = await _userManager.AuthenticateUser(current.Username, request.Password, ip, isUserSession: false).ConfigureAwait(false);
            if (user is null || user.Id != userId)
            {
                _throttle.RegisterFailure(ip, current.Username);
                return Fail();
            }

            var token = _tickets.Issue(userId, user.Username, ip, request.DeviceId, "Rotation", needsEnrollment: false, isRotation: true);
            var ticket = _tickets.Get(token, ip, request.DeviceId);
            if (token is null || ticket is null)
            {
                return Fail();
            }

            var secret = _tickets.GetOrCreatePendingSecret(ticket, TotpService.GenerateSecret);
            var issuer = Plugin.Instance?.Configuration.Issuer ?? "Jellyfin";
            return Ok(new ManageBeginResponse
            {
                Ticket = token,
                OtpAuthUri = TotpService.BuildOtpAuthUri(issuer, user.Username, secret, _totp.Options),
                Secret = Base32.Encode(secret)
            });
        }
        catch (Exception ex)
        {
            _throttle.RegisterFailure(ip, null);
            _logger.LogInformation("TwoFactor: seed rotation denied for user {UserId} (IP: {IP}, {Reason}).", userId, ip, ex.GetType().Name);
            return Fail();
        }
    }

    /// <summary>
    /// Rotation, part 2: checks the first code of the new authenticator and, only then, replaces the old seed.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>200, or a uniform error.</returns>
    [HttpPost("Manage/Confirm")]
    public async Task<ActionResult> ManageConfirm([FromBody] ManageConfirmRequest request)
    {
        var ip = GetIp();
        if (!TryGetSessionUserId(out var userId) || _throttle.IsBlocked(ip, null))
        {
            return Fail();
        }

        var ticket = _tickets.Get(request.Ticket, ip, request.DeviceId ?? string.Empty);
        if (ticket is null || !ticket.IsRotation || ticket.UserId != userId || ticket.PendingSecret is null)
        {
            return Fail();
        }

        if (!TotpService.TryValidate(ticket.PendingSecret, request.Code, _time.GetUtcNow(), -1, _totp.Options, out var counter))
        {
            _tickets.RegisterFailure(request.Ticket!);
            _throttle.RegisterFailure(ip, ticket.Username);
            return Fail();
        }

        if (!_tickets.Consume(request.Ticket!))
        {
            return Fail();
        }

        try
        {
            if (!_seeds.TryReplace(userId, ticket.PendingSecret, counter, _totp.Options))
            {
                return Fail();
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: the seed store is not usable.");
            return Fail();
        }

        _logger.LogInformation("TwoFactor: authenticator replaced by user {UserId}.", userId);
        var closed = request.CloseOtherSessions && await CloseOtherSessions(userId).ConfigureAwait(false);
        return Ok(new { ok = true, closedOtherSessions = closed });
    }

    /// <summary>
    /// Deletes the authenticator of one user so that they enroll a new one at their next login.
    /// Administrators only. All of the user's sessions are closed too (the administrator's own session is kept if they reset themselves); the password is not touched.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>200 with whether there was a seed, or an error.</returns>
    [HttpPost("Admin/Reset")]
    [Authorize(Policy = ElevationPolicy)]
    public async Task<ActionResult> AdminReset([FromBody] AdminResetRequest request)
    {
        if (!_seeds.IsAvailable)
        {
            return Fail();
        }

        var user = Guid.TryParse(request.UserId, out var id)
            ? _userManager.GetUserById(id)
            : (string.IsNullOrWhiteSpace(request.Username) ? null : _userManager.GetUserByName(request.Username));
        if (user is null)
        {
            return NotFound(new ErrorResponse { Error = "Usuario no encontrado." });
        }

        try
        {
            var hadSeed = _seeds.Remove(user.Id);
            // A code from before the reset must not let anyone enroll: the next one has to be generated again.
            _invites.Revoke(user.Id);
            _logger.LogWarning(
                "TwoFactor: authenticator of user {UserId} reset by administrator {AdminId} (had one: {HadSeed}).",
                user.Id,
                TryGetSessionUserId(out var adminId) ? adminId : Guid.Empty,
                hadSeed);
            // The user's sessions are closed too: whoever held the old authenticator (or a stolen session) must start over.
            // If the administrator resets their own authenticator, their current session is kept.
            var isSelf = TryGetSessionUserId(out var callerId) && callerId == user.Id;
            var closed = await RevokeSessions(user.Id, isSelf ? User.FindFirst(TokenClaim)?.Value : string.Empty, isSelf).ConfigureAwait(false);
            return Ok(new { ok = true, hadSeed, closedSessions = closed });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: the seed store is not usable.");
            return Fail();
        }
    }

    // Revokes every access token of the user except the one of this request (ISessionManager.RevokeUserTokens).
    private Task<bool> CloseOtherSessions(Guid userId) => RevokeSessions(userId, User.FindFirst(TokenClaim)?.Value, tokenRequired: true);

    // Revokes every access token of the user except keepToken (an empty text keeps none).
    private async Task<bool> RevokeSessions(Guid userId, string? keepToken, bool tokenRequired)
    {
        if (tokenRequired && string.IsNullOrEmpty(keepToken))
        {
            // Without the current token the call would also close this very session: do nothing instead.
            _logger.LogWarning("TwoFactor: the sessions of user {UserId} were not closed because the current token is unknown.", userId);
            return false;
        }

        try
        {
            await _sessionManager.RevokeUserTokens(userId, keepToken ?? string.Empty).ConfigureAwait(false);
            _logger.LogInformation("TwoFactor: sessions of user {UserId} closed (current one kept: {Kept}).", userId, !string.IsNullOrEmpty(keepToken));
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("TwoFactor: closing the sessions of user {UserId} failed ({Reason}).", userId, ex.GetType().Name);
            return false;
        }
    }

    private bool TryGetSessionUserId(out Guid userId)
    {
        userId = Guid.Empty;
        return Guid.TryParse(User.FindFirst(UserIdClaim)?.Value, out userId) && userId != Guid.Empty;
    }

    private string GetIp() => HttpContext.GetNormalizedRemoteIP().ToString();

    private ActionResult Fail() => Unauthorized(new ErrorResponse());
}
