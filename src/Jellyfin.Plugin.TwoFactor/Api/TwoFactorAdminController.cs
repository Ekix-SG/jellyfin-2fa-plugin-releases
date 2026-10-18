using System;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.TwoFactor.Storage;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Api;

/// <summary>
/// Administrators' endpoints for the invitation codes that let a user enroll an authenticator.
/// Nothing here is anonymous: every route needs a session that passes Jellyfin's <c>RequiresElevation</c> policy.
/// The reset of an authenticator (<c>Admin/Reset</c>) lives in <see cref="TwoFactorManageController"/> because it also closes sessions.
/// Not marked <c>[ApiController]</c>, for the same reason as <see cref="TwoFactorController"/>.
/// </summary>
[Authorize(Policy = "RequiresElevation")]
[UniformErrorFilter]
[Route("TwoFactor/Admin")]
public class TwoFactorAdminController : ControllerBase
{
    // Claim that Jellyfin's authentication handler puts the user id in (InternalClaimTypes.UserId).
    private const string UserIdClaim = "Jellyfin-UserId";

    private readonly IUserManager _userManager;
    private readonly ISeedStore _seeds;
    private readonly IInviteStore _invites;
    private readonly ILogger<TwoFactorAdminController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TwoFactorAdminController"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="seeds">The seed store.</param>
    /// <param name="invites">The invitation code store.</param>
    /// <param name="logger">The logger.</param>
    public TwoFactorAdminController(
        IUserManager userManager,
        ISeedStore seeds,
        IInviteStore invites,
        ILogger<TwoFactorAdminController> logger)
    {
        _userManager = userManager;
        _seeds = seeds;
        _invites = invites;
        _logger = logger;
    }

    /// <summary>
    /// Lists the users with their state: enrolled or not, and until when their invitation code is valid.
    /// </summary>
    /// <returns>The rows, ordered by name.</returns>
    [HttpGet("Users")]
    public ActionResult ListUsers()
    {
        if (!_seeds.IsAvailable || !_invites.IsAvailable)
        {
            return Fail();
        }

        try
        {
            var rows = _userManager.GetUsers()
                .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)
                .Select(u => new AdminUserRow
                {
                    Id = u.Id.ToString("N"),
                    Name = u.Username,
                    Enrolled = _seeds.IsEnabled(u.Id),
                    InviteExpiresAt = _invites.GetActive(u.Id)?.ExpiresAt
                })
                .ToList();
            NoStore();
            return Ok(rows);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: a store is not usable.");
            return Fail();
        }
    }

    /// <summary>
    /// Generates an invitation code for a user who has no authenticator. Any earlier code of that user stops working.
    /// The plain code is in this answer and nowhere else: it is not stored and not logged.
    /// </summary>
    /// <param name="request">The user, by id or by name.</param>
    /// <returns>The code and its expiry.</returns>
    [HttpPost("Invite")]
    public ActionResult CreateInvite([FromBody] AdminResetRequest request)
    {
        if (!_seeds.IsAvailable || !_invites.IsAvailable)
        {
            return Fail();
        }

        var user = FindUser(request);
        if (user is null)
        {
            return NotFound(new ErrorResponse { Error = "Usuario no encontrado." });
        }

        try
        {
            if (_seeds.IsEnabled(user.Id))
            {
                return Conflict(new ErrorResponse { Error = "El usuario ya tiene autenticador: restablécelo primero." });
            }

            var ttl = Plugin.Instance?.Configuration.InviteTtl ?? TimeSpan.FromHours(24);
            var invite = _invites.Create(user.Id, ttl);
            _logger.LogInformation(
                "TwoFactor: invitation code generated for user {UserId} by administrator {AdminId}, valid until {ExpiresAt:u}.",
                user.Id,
                GetAdminId(),
                invite.ExpiresAt);
            NoStore();
            return Ok(new AdminInviteResponse { UserId = user.Id.ToString("N"), Code = invite.Code, ExpiresAt = invite.ExpiresAt });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: a store is not usable.");
            return Fail();
        }
    }

    /// <summary>
    /// Revokes the live invitation code of a user.
    /// </summary>
    /// <param name="request">The user, by id or by name.</param>
    /// <returns>200 with whether there was a code, or an error.</returns>
    [HttpPost("Invite/Revoke")]
    public ActionResult RevokeInvite([FromBody] AdminResetRequest request)
    {
        if (!_invites.IsAvailable)
        {
            return Fail();
        }

        var user = FindUser(request);
        if (user is null)
        {
            return NotFound(new ErrorResponse { Error = "Usuario no encontrado." });
        }

        try
        {
            var had = _invites.Revoke(user.Id);
            _logger.LogInformation(
                "TwoFactor: invitation code of user {UserId} revoked by administrator {AdminId} (had one: {HadInvite}).",
                user.Id,
                GetAdminId(),
                had);
            return Ok(new { ok = true, hadInvite = had });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: the invitation store is not usable.");
            return Fail();
        }
    }

    private Jellyfin.Database.Implementations.Entities.User? FindUser(AdminResetRequest request)
        => Guid.TryParse(request.UserId, out var id)
            ? _userManager.GetUserById(id)
            : (string.IsNullOrWhiteSpace(request.Username) ? null : _userManager.GetUserByName(request.Username));

    private Guid GetAdminId() => Guid.TryParse(User.FindFirst(UserIdClaim)?.Value, out var id) ? id : Guid.Empty;

    private void NoStore() => Response.Headers["Cache-Control"] = "no-store";

    private ActionResult Fail() => Unauthorized(new ErrorResponse());
}
