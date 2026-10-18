using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
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
/// Anonymous endpoints of the two-step login. The final route is <c>[BaseUrl]/TwoFactor/...</c>.
/// Nothing here may be reached with a session: opening one is the whole point.
/// Not marked <c>[ApiController]</c> on purpose: its automatic 400 for a malformed body is replaced by
/// <see cref="UniformErrorFilterAttribute"/>, which answers the same 401 as any other failure.
/// </summary>
[AllowAnonymous]
[UniformErrorFilter]
[Route("TwoFactor")]
public class TwoFactorController : ControllerBase
{
    private const string ClientName = "Jellyfin Web";
    private const int MaxFieldLength = 256;

    private static readonly Lazy<string> LoginHtml = new(() => ReadResource("login.html"));
    private static readonly Lazy<string> I18nScript = new(() => ReadResource("i18n.js"));
    private static readonly Lazy<string> AdminHtml = new(() => ReadResource("admin.html"));
    private static readonly Lazy<string> ManageHtml = new(() => ReadResource("manage.html"));
    private static readonly Lazy<string> QrScript = new(() => ReadResource("qrcode.js"));
    private static readonly Lazy<string> RedirectScript = new(() => ReadResource("redirect.js"));

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ISeedStore _seeds;
    private readonly IInviteStore _invites;
    private readonly TotpSettings _totp;
    private readonly TicketStore _tickets;
    private readonly LoginThrottle _throttle;
    private readonly TimeProvider _time;
    private readonly ILogger<TwoFactorController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TwoFactorController"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="seeds">The seed store.</param>
    /// <param name="invites">The invitation code store.</param>
    /// <param name="totp">The TOTP options for new enrollments.</param>
    /// <param name="tickets">The ticket store.</param>
    /// <param name="throttle">The temporary block by IP and user name.</param>
    /// <param name="time">The clock.</param>
    /// <param name="logger">The logger.</param>
    public TwoFactorController(
        IUserManager userManager,
        ISessionManager sessionManager,
        ISeedStore seeds,
        IInviteStore invites,
        TotpSettings totp,
        TicketStore tickets,
        LoginThrottle throttle,
        TimeProvider time,
        ILogger<TwoFactorController> logger)
    {
        _userManager = userManager;
        _sessionManager = sessionManager;
        _seeds = seeds;
        _invites = invites;
        _totp = totp;
        _tickets = tickets;
        _throttle = throttle;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Gets the login page.
    /// </summary>
    /// <returns>The HTML page.</returns>
    [HttpGet("Login")]
    [Produces("text/html")]
    public ContentResult GetLoginPage()
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Content(LoginHtml.Value, "text/html; charset=utf-8");
    }

    /// <summary>
    /// Gets the page where a signed-in user replaces their own authenticator. The page itself holds nothing
    /// secret: it reads the session token from the browser and calls the endpoints of <see cref="TwoFactorManageController"/>.
    /// </summary>
    /// <returns>The HTML page.</returns>
    [HttpGet("Manage")]
    [Produces("text/html")]
    public ContentResult GetManagePage()
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Content(ManageHtml.Value, "text/html; charset=utf-8");
    }

    /// <summary>
    /// Gets the administrators' page that resets a user's authenticator. Like the manage page it holds nothing secret:
    /// it checks in the browser that the session is an administrator's, and the reset itself is authorized by the server.
    /// </summary>
    /// <returns>The HTML page.</returns>
    [HttpGet("Admin")]
    [Produces("text/html")]
    public ContentResult GetAdminPage()
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Content(AdminHtml.Value, "text/html; charset=utf-8");
    }

    /// <summary>
    /// Gets the embedded translation script shared by the plugin's pages.
    /// </summary>
    /// <returns>The script.</returns>
    [HttpGet("i18n.js")]
    [Produces("text/javascript")]
    public ContentResult GetI18nScript() => Content(I18nScript.Value, "text/javascript; charset=utf-8");

    /// <summary>
    /// Gets the embedded QR code generator script.
    /// </summary>
    /// <returns>The script.</returns>
    [HttpGet("qrcode.js")]
    [Produces("text/javascript")]
    public ContentResult GetQrScript() => Content(QrScript.Value, "text/javascript; charset=utf-8");

    /// <summary>
    /// Gets the script that the plugin injects into the web client to replace its login route.
    /// </summary>
    /// <returns>The script.</returns>
    [HttpGet("redirect.js")]
    [Produces("text/javascript")]
    public ContentResult GetRedirectScript()
    {
        Response.Headers["Cache-Control"] = "no-cache";
        return Content(RedirectScript.Value, "text/javascript; charset=utf-8");
    }

    /// <summary>
    /// Step 1: checks user name and password and issues a ticket.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>A ticket, or a uniform error.</returns>
    [HttpPost("Step1")]
    public async Task<ActionResult> Step1([FromBody] Step1Request request)
    {
        var ip = GetIp();
        if (!_seeds.IsAvailable || !_totp.IsValid)
        {
            _logger.LogWarning(
                "TwoFactor: login refused because the configuration is invalid: {Variable} must be valid and the TOTP variables must be unset or valid (see the start-up log and the README).",
                SeedCipher.KeyEnvironmentVariable);
            return Fail();
        }

        if (!IsValidField(request.Username) || !IsValidPassword(request.Password) || !IsValidDeviceId(request.DeviceId))
        {
            return Fail();
        }

        if (_throttle.IsBlocked(ip, request.Username))
        {
            _logger.LogInformation("TwoFactor step 1 refused: too many failures (IP: {IP}).", ip);
            return Fail();
        }

        try
        {
            // Applies Jellyfin's own checks that AuthenticateDirect skips: disabled account,
            // remote access, parental schedule, failed-login counter (UserManager.cs AuthenticateUser).
            var user = await _userManager.AuthenticateUser(request.Username!, request.Password!, ip, isUserSession: false).ConfigureAwait(false);
            if (user is null)
            {
                _throttle.RegisterFailure(ip, request.Username);
                return Fail();
            }

            var deviceName = string.IsNullOrWhiteSpace(request.DeviceName) || request.DeviceName.Length > 64
                ? "Web Browser"
                : request.DeviceName;
            var needsEnrollment = !_seeds.IsEnabled(user.Id);
            var token = _tickets.Issue(user.Id, user.Username, ip, request.DeviceId!, deviceName, needsEnrollment);
            if (token is null)
            {
                return Fail();
            }

            return Ok(new Step1Response { Ticket = token, NeedsEnrollment = needsEnrollment });
        }
        catch (Exception ex)
        {
            // Wrong password, unknown user, disabled account... all look the same to the caller.
            _throttle.RegisterFailure(ip, request.Username);
            _logger.LogInformation("TwoFactor step 1 denied (IP: {IP}, {Reason}).", ip, ex.GetType().Name);
            return Fail();
        }
    }

    /// <summary>
    /// Enrollment, part 1: checks the invitation code an administrator gave to the user and generates the pending secret
    /// for the ticket. The password alone never enrolls anyone. The code is not used up here (see <see cref="EnrollConfirm"/>).
    /// Every failure gives the same answer, whatever the cause.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The otpauth URI and the secret.</returns>
    [HttpPost("Enroll/Begin")]
    public ActionResult EnrollBegin([FromBody] EnrollBeginRequest request)
    {
        var ip = GetIp();
        var ticket = _tickets.Get(request.Ticket, ip, request.DeviceId ?? string.Empty);
        if (ticket is null || !ticket.NeedsEnrollment || ticket.IsRotation || !_invites.IsAvailable
            || _throttle.IsBlocked(ip, ticket.Username))
        {
            return Fail();
        }

        try
        {
            if (_seeds.IsEnabled(ticket.UserId))
            {
                return Fail();
            }

            var inviteId = _invites.TryValidate(ticket.UserId, request.InviteCode);
            if (inviteId is null)
            {
                _invites.RegisterFailure(ticket.UserId);
                _tickets.RegisterFailure(request.Ticket!);
                _throttle.RegisterFailure(ip, ticket.Username);
                _logger.LogInformation("TwoFactor enrollment denied for user {UserId} (IP: {IP}).", ticket.UserId, ip);
                return Fail();
            }

            _tickets.AttachInvite(ticket, inviteId.Value);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: the invitation store is not usable.");
            return Fail();
        }

        var secret = _tickets.GetOrCreatePendingSecret(ticket, TotpService.GenerateSecret);
        var issuer = Plugin.Instance?.Configuration.Issuer ?? "Jellyfin";
        return Ok(new EnrollBeginResponse
        {
            OtpAuthUri = TotpService.BuildOtpAuthUri(issuer, ticket.Username, secret, _totp.Options),
            Secret = Base32.Encode(secret)
        });
    }

    /// <summary>
    /// Enrollment, part 2: checks the first code, stores the seed and opens the session.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The session data, or a uniform error.</returns>
    [HttpPost("Enroll/Confirm")]
    public async Task<ActionResult> EnrollConfirm([FromBody] CodeRequest request)
    {
        var ip = GetIp();
        var ticket = _tickets.Get(request.Ticket, ip, request.DeviceId ?? string.Empty);
        if (ticket is null || !ticket.NeedsEnrollment || ticket.PendingSecret is null || ticket.InviteId is not { } inviteId
            || _throttle.IsBlocked(ip, ticket.Username))
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
            // The administrator may have revoked or replaced the code since enrollment began.
            if (!_invites.IsActive(inviteId) || !_seeds.TryEnroll(ticket.UserId, ticket.PendingSecret, counter, _totp.Options))
            {
                return Fail();
            }

            // The code is used up only now that the seed is stored. If it was revoked in the meantime, undo the enrollment.
            if (!_invites.Consume(inviteId))
            {
                _seeds.Remove(ticket.UserId);
                return Fail();
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: the seed store is not usable.");
            return Fail();
        }

        _logger.LogInformation("TwoFactor: authenticator enrolled for user {UserId}.", ticket.UserId);
        return await OpenSession(ticket, ip).ConfigureAwait(false);
    }

    /// <summary>
    /// Step 2: checks the TOTP code for a ticket, consumes it and opens the session.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The session data, or a uniform error.</returns>
    [HttpPost("Step2")]
    public async Task<ActionResult> Step2([FromBody] CodeRequest request)
    {
        var ip = GetIp();
        var ticket = _tickets.Get(request.Ticket, ip, request.DeviceId ?? string.Empty);
        if (ticket is null || ticket.NeedsEnrollment || ticket.IsRotation || _throttle.IsBlocked(ip, ticket.Username))
        {
            return Fail();
        }

        bool accepted;
        try
        {
            accepted = _seeds.TryAcceptCode(ticket.UserId, request.Code, _time.GetUtcNow());
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "TwoFactor: the seed store is not usable.");
            return Fail();
        }

        if (!accepted)
        {
            _logger.LogInformation("TwoFactor step 2 denied for user {UserId} (IP: {IP}).", ticket.UserId, ip);
            _tickets.RegisterFailure(request.Ticket!);
            _throttle.RegisterFailure(ip, ticket.Username);
            return Fail();
        }

        if (!_tickets.Consume(request.Ticket!))
        {
            return Fail();
        }

        return await OpenSession(ticket, ip).ConfigureAwait(false);
    }

    private static string ReadResource(string name)
    {
        var assembly = typeof(TwoFactorController).Assembly;
        using var stream = assembly.GetManifestResourceStream("Jellyfin.Plugin.TwoFactor.Web." + name)
            ?? throw new FileNotFoundException("Embedded resource not found: " + name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static bool IsValidField(string? value) => !string.IsNullOrEmpty(value) && value.Length <= MaxFieldLength;

    // Jellyfin allows accounts with an empty password (new users, and users whose password was reset),
    // and with password-only login blocked this page is their only way in. Null is rejected.
    private static bool IsValidPassword(string? value) => value is not null && value.Length <= MaxFieldLength;

    private static bool IsValidDeviceId(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= MaxFieldLength;

    private string GetIp() => HttpContext.GetNormalizedRemoteIP().ToString();

    private ActionResult Fail() => Unauthorized(new ErrorResponse());

    /// <summary>
    /// Redeems a password reset PIN and sets the new password in one step.
    /// The PIN is the one Jellyfin wrote to a file on the server (<c>POST /Users/ForgotPassword</c>).
    /// Jellyfin's own redeem call leaves the password equal to the PIN; here it is replaced at once by the
    /// password the user chose. The TOTP seed is never touched: the second factor stays required.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>200 on success, or an error.</returns>
    [HttpPost("ResetPassword")]
    public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        // Validate everything before the PIN is redeemed, because redeeming it already changes the password.
        if (string.IsNullOrWhiteSpace(request.Pin) || request.Pin.Length > MaxFieldLength
            || string.IsNullOrEmpty(request.NewPassword) || request.NewPassword.Length > MaxFieldLength)
        {
            return Unauthorized(new ErrorResponse { Error = "PIN o contraseña no válidos." });
        }

        var ip = GetIp();
        if (_throttle.IsBlocked(ip, null))
        {
            return Unauthorized(new ErrorResponse { Error = "PIN incorrecto o caducado." });
        }

        try
        {
            var result = await _userManager.RedeemPasswordResetPin(request.Pin).ConfigureAwait(false);
            if (!result.Success)
            {
                _throttle.RegisterFailure(ip, null);
                return Unauthorized(new ErrorResponse { Error = "PIN incorrecto o caducado." });
            }

            foreach (var name in result.UsersReset)
            {
                var user = _userManager.GetUserByName(name);
                if (user is not null)
                {
                    await _userManager.ChangePassword(user.Id, request.NewPassword).ConfigureAwait(false);
                    _logger.LogInformation("TwoFactor: password reset by PIN for user {UserId}.", user.Id);
                }
            }

            return Ok(new { ok = true });
        }
        catch (Exception ex)
        {
            _logger.LogInformation("TwoFactor: password reset denied ({Reason}).", ex.GetType().Name);
            return Unauthorized(new ErrorResponse { Error = "PIN incorrecto o caducado." });
        }
    }

    private async Task<ActionResult> OpenSession(Ticket ticket, string ip)
    {
        // Re-check the account: the ticket may be up to two minutes old.
        var user = _userManager.GetUserById(ticket.UserId);
        if (user is null || user.HasPermission(PermissionKind.IsDisabled))
        {
            return Fail();
        }

        try
        {
            // AuthenticateDirect does not check any password: both factors were verified above.
            // It still enforces the device allow-list and the maximum number of sessions.
            var result = await _sessionManager.AuthenticateDirect(new AuthenticationRequest
            {
                UserId = ticket.UserId,
                Username = ticket.Username,
                App = ClientName,
                AppVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.1.0.0",
                DeviceId = ticket.DeviceId,
                DeviceName = ticket.DeviceName,
                RemoteEndPoint = ip
            }).ConfigureAwait(false);

            _throttle.RegisterSuccess(ticket.Username);
            _logger.LogInformation("TwoFactor: session opened for user {UserId} (IP: {IP}).", ticket.UserId, ip);
            return Ok(new SessionResponse
            {
                AccessToken = result.AccessToken,
                UserId = result.User.Id.ToString("N"),
                ServerId = result.ServerId
            });
        }
        catch (Exception ex)
        {
            _logger.LogInformation("TwoFactor: session refused for user {UserId} ({Reason}).", ticket.UserId, ex.GetType().Name);
            return Fail();
        }
    }
}
