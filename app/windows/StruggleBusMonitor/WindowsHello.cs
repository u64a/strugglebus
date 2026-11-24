using Windows.Security.Credentials.UI;

namespace StruggleBusMonitor;

/// <summary>The Windows credential prompt, as far as this app uses it.</summary>
internal interface IUserConsent
{
    Task<UserConsentVerifierAvailability> CheckAvailabilityAsync();
    Task<UserConsentVerificationResult> RequestVerificationAsync(string message);
}

/// <summary>The real prompt. It shows Windows UI, so nothing but these two calls belongs here.</summary>
internal sealed class SystemUserConsent : IUserConsent
{
    public Task<UserConsentVerifierAvailability> CheckAvailabilityAsync() =>
        UserConsentVerifier.CheckAvailabilityAsync().AsTask();

    public Task<UserConsentVerificationResult> RequestVerificationAsync(string message) =>
        UserConsentVerifier.RequestVerificationAsync(message).AsTask();
}

public sealed class WindowsHello
{
    private readonly IUserConsent _consent;

    public WindowsHello() : this(new SystemUserConsent())
    {
    }

    internal WindowsHello(IUserConsent consent) => _consent = consent;

    public async Task<bool> VerifyAsync(string message)
    {
        var availability = await _consent.CheckAvailabilityAsync();
        if (availability != UserConsentVerifierAvailability.Available)
            throw new InvalidOperationException(DescribeUnavailable(availability));
        var result = await _consent.RequestVerificationAsync(message);
        return result == UserConsentVerificationResult.Verified;
    }

    /// <summary>Why Windows Hello cannot confirm an action, and what to do about it.</summary>
    internal static string DescribeUnavailable(UserConsentVerifierAvailability availability) => availability switch
    {
        UserConsentVerifierAvailability.NotConfiguredForUser =>
            "Windows Hello is not set up for your Windows account. Set up a PIN in Windows Settings > Accounts > Sign-in options, then try again.",
        UserConsentVerifierAvailability.DeviceNotPresent =>
            "Windows Hello has nothing to sign in with on this PC. Set up a PIN in Windows Settings > Accounts > Sign-in options, then try again.",
        UserConsentVerifierAvailability.DisabledByPolicy =>
            "Windows Hello is turned off on this PC by a policy. Ask whoever manages this PC to allow it.",
        UserConsentVerifierAvailability.DeviceBusy =>
            "Windows Hello is busy with another request. Close any other Windows sign-in prompt and try again.",
        _ => $"Windows Hello is unavailable ({availability})."
    };
}
