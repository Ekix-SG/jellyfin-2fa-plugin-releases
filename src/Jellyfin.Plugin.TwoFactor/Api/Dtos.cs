using System;
using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.TwoFactor.Api;

/// <summary>Body of step 1.</summary>
public class Step1Request
{
    /// <summary>Gets or sets the user name.</summary>
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    /// <summary>Gets or sets the password. Never logged.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary>Gets or sets the web client device id.</summary>
    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }

    /// <summary>Gets or sets the web client device name.</summary>
    [JsonPropertyName("deviceName")]
    public string? DeviceName { get; set; }
}

/// <summary>Response of step 1.</summary>
public class Step1Response
{
    /// <summary>Gets or sets the ticket.</summary>
    [JsonPropertyName("ticket")]
    public string Ticket { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether the user must enroll an authenticator first.</summary>
    [JsonPropertyName("needsEnrollment")]
    public bool NeedsEnrollment { get; set; }
}

/// <summary>Body of enrollment begin.</summary>
public class TicketRequest
{
    /// <summary>Gets or sets the ticket.</summary>
    [JsonPropertyName("ticket")]
    public string? Ticket { get; set; }

    /// <summary>Gets or sets the device id the ticket was issued for.</summary>
    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }
}

/// <summary>Body of enrollment begin: the ticket plus the invitation code an administrator gave to the user.</summary>
public class EnrollBeginRequest : TicketRequest
{
    /// <summary>Gets or sets the invitation code. Never logged.</summary>
    [JsonPropertyName("inviteCode")]
    public string? InviteCode { get; set; }
}

/// <summary>Body of enrollment confirm and of step 2.</summary>
public class CodeRequest : TicketRequest
{
    /// <summary>Gets or sets the TOTP code. Never logged.</summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }
}

/// <summary>Response of enrollment begin.</summary>
public class EnrollBeginResponse
{
    /// <summary>Gets or sets the otpauth URI for the QR code.</summary>
    [JsonPropertyName("otpauthUri")]
    public string OtpAuthUri { get; set; } = string.Empty;

    /// <summary>Gets or sets the Base32 secret for manual entry.</summary>
    [JsonPropertyName("secret")]
    public string Secret { get; set; } = string.Empty;
}

/// <summary>Response when a session was opened.</summary>
public class SessionResponse
{
    /// <summary>Gets or sets the access token.</summary>
    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>Gets or sets the user id.</summary>
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>Gets or sets the server id.</summary>
    [JsonPropertyName("serverId")]
    public string ServerId { get; set; } = string.Empty;
}

/// <summary>Uniform error body.</summary>
public class ErrorResponse
{
    /// <summary>Gets or sets the message.</summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = "Credenciales o código incorrectos.";
}

/// <summary>Body of the password reset.</summary>
public class ResetPasswordRequest
{
    /// <summary>Gets or sets the PIN that Jellyfin wrote to a file on the server.</summary>
    [JsonPropertyName("pin")]
    public string? Pin { get; set; }

    /// <summary>Gets or sets the new password. Never logged.</summary>
    [JsonPropertyName("newPassword")]
    public string? NewPassword { get; set; }
}

/// <summary>Body of the start of a seed rotation by a signed-in user.</summary>
public class ManageBeginRequest
{
    /// <summary>Gets or sets the user's current password. Never logged.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary>Gets or sets the web client device id.</summary>
    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }
}

/// <summary>Response of the start of a seed rotation.</summary>
public class ManageBeginResponse : EnrollBeginResponse
{
    /// <summary>Gets or sets the rotation ticket, to be sent back with the first code of the new authenticator.</summary>
    [JsonPropertyName("ticket")]
    public string Ticket { get; set; } = string.Empty;
}

/// <summary>Body of an administrator reset of one user's authenticator.</summary>
public class AdminResetRequest
{
    /// <summary>Gets or sets the user id (any format Guid.TryParse accepts). Optional if the user name is given.</summary>
    [JsonPropertyName("userId")]
    public string? UserId { get; set; }

    /// <summary>Gets or sets the user name. Optional if the user id is given.</summary>
    [JsonPropertyName("username")]
    public string? Username { get; set; }
}

/// <summary>Body of the end of a seed rotation.</summary>
public class ManageConfirmRequest : CodeRequest
{
    /// <summary>Gets or sets a value indicating whether the user's other sessions are closed once the seed is replaced.</summary>
    [JsonPropertyName("closeOtherSessions")]
    public bool CloseOtherSessions { get; set; }
}

/// <summary>One row of the administrators' user list.</summary>
public class AdminUserRow
{
    /// <summary>Gets or sets the user id.</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>Gets or sets the user name.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether the user has an authenticator.</summary>
    [JsonPropertyName("enrolled")]
    public bool Enrolled { get; set; }

    /// <summary>Gets or sets when the user's live invitation code expires, or <c>null</c> if there is none.</summary>
    [JsonPropertyName("inviteExpiresAt")]
    public DateTimeOffset? InviteExpiresAt { get; set; }
}

/// <summary>Response of the generation of an invitation code. The only time the plain code is available.</summary>
public class AdminInviteResponse
{
    /// <summary>Gets or sets the user id.</summary>
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>Gets or sets the plain code.</summary>
    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;

    /// <summary>Gets or sets when the code expires.</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; set; }
}
