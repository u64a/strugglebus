using System.Net;
using System.Net.Sockets;

namespace StruggleBusMonitor;

/// <summary>A host that joined with a host code, with what the bus recorded and what the host says of itself.</summary>
internal sealed record HostJoin(string AgentId, string AgentName, ManagedServicePrincipal Principal, HostStatus? Status)
{
    public string Code => HostsLogic.ConfirmationCode(AgentId, Principal.HostRedeemRequestId!);
}

/// <summary>
/// Step 10 of Add a host, in words: the comparison the operator makes before a new host is added
/// to the fleet, what is said when it does not match, and what they are shown before the new
/// document is saved for signing. The app signs nothing; see <see cref="FleetPublishLogic"/>.
/// </summary>
internal static class FleetJoinLogic
{
    public const string CompareCaption = "Compare the confirmation code";
    public const string NoMatchCaption = "The code does not match";
    public const string SignCaption = "Review what will be signed";
    public const string RevokeAction = "revoke";
    public const string RetireAction = "retire";

    public const string NoFleetYet =
        "The bus holds no fleet document yet. Publish today's signed fleet first, with Publish a signed fleet document below; a host can then be added to it.";

    public const string NothingChanged = "Nothing was changed and nothing was saved. The host stays out of the fleet.";

    /// <summary>
    /// True for an address a host on the site's own network would have: private IPv4 ranges,
    /// loopback, link-local, and IPv6 unique-local. Anything else redeemed the code from outside.
    /// </summary>
    public static bool IsLocalAddress(string? address)
    {
        if (!IPAddress.TryParse(address, out var parsed)) return false;
        var plain = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return IPAddress.IsLoopback(plain) || (plain.AddressFamily == AddressFamily.InterNetwork ? IsPrivateV4(plain) : IsLocalV6(plain));
    }

    private static bool IsLocalV6(IPAddress address) => address.IsIPv6LinkLocal || address.IsIPv6UniqueLocal;

    /// <summary>10/8, 172.16/12, 192.168/16 and link-local 169.254/16, as network and mask.</summary>
    private static readonly (uint Network, uint Mask)[] PrivateV4 =
    [
        (0x0A000000, 0xFF000000), (0xAC100000, 0xFFF00000), (0xC0A80000, 0xFFFF0000), (0xA9FE0000, 0xFFFF0000)
    ];

    private static bool IsPrivateV4(IPAddress address)
    {
        var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        return PrivateV4.Any(range => (value & range.Mask) == range.Network);
    }

    /// <summary>Where the code was redeemed from, with a warning when that is not an address on a local network.</summary>
    internal static string RedeemedLine(string? address)
    {
        if (string.IsNullOrEmpty(address)) return "Redeemed from:      the bus did not record an address";
        return IsLocalAddress(address)
            ? $"Redeemed from:      {address}"
            : $"Redeemed from:      {address}   <<< WARNING: not an address on a local network";
    }

    private static string Reported(string value) => value.Length > 0 ? value : "(not reported)";

    /// <summary>What the host says about itself. It is the host's own word and proves nothing; it is shown so a wrong PC stands out.</summary>
    internal static IEnumerable<string> ReportedLines(HostStatus? status)
    {
        if (status is null) return ["The host has not reported its status yet."];
        return
        [
            "As the host itself reports (not checked):",
            $"  PC name:          {Reported(status.Host)}",
            $"  Windows account:  {Reported(status.Account)}",
            $"  Engines:          {Reported(string.Join(", ", status.Engines.Select(engine => engine.Name)))}",
            $"  Warnings:         {Reported(string.Join(", ", status.Warnings))}"
        ];
    }

    /// <summary>The question asked before anything else. Yes means the code matches the installer's.</summary>
    public static string CompareText(HostJoin join) => string.Join("\n",
    [
        $"A new worker host asks to join the fleet as {join.AgentName}.",
        "",
        $"Confirmation code:  {join.Code}",
        RedeemedLine(join.Principal.HostRedeemedFrom),
        $"Service principal:  {join.Principal.Name}",
        $"Agent id:           {join.AgentId}",
        "",
        .. ReportedLines(join.Status),
        "",
        "The installer on that PC printed a confirmation code when it finished. Only the PC that used the one-time code can print the same one.",
        "",
        "Is the code above exactly the code the installer printed?",
        "Yes: go on to add this host to the fleet.   No: nothing is added."
    ]);

    /// <summary>Asked after a No. Yes shuts out whoever redeemed the code; No leaves everything as it is.</summary>
    public static string NoMatchText(HostJoin join) => string.Join("\n",
    [
        $"If the codes differ, the one-time code for {join.AgentName} was used by something other than the installer you ran: a copied data file, or the wrong PC.",
        "",
        $"Shut it out now? This revokes the service principal {join.Principal.Name} and retires the agent {join.AgentName}. Both are permanent. The fleet is not changed.",
        "",
        "Yes: revoke and retire (Windows Hello confirms).   No: change nothing, for example if you only mistyped or want to check the PC again."
    ]);

    public static string RetireHelloPrompt(HostJoin join) => $"Revoke {join.Principal.Name} and retire {join.AgentName}";

    public static string RetireReason(HostJoin join) =>
        $"Add a host: confirmation code for {join.AgentName} did not match the installer's";

    public static string RetiredText(HostJoin join, bool principalRevoked, bool agentRetired) =>
        $"The code did not match. Service principal {join.Principal.Name}: {(principalRevoked ? "revoked" : "NOT revoked, the bus offers no revoke for it; do it on the Service principals tab")}. " +
        $"Agent {join.AgentName}: {(agentRetired ? "retired" : "NOT retired, the bus offers no retire for it; do it on the Agents tab")}. The fleet was not changed.\n\n" +
        OtherAgentsWarning(join);

    /// <summary>
    /// Revoking the principal stops it registering more agents; it does not retire ones it already
    /// made. Whoever held a stolen code may have registered more than the host agent.
    /// </summary>
    public static string OtherAgentsWarning(HostJoin join) =>
        $"Only the host agent was retired. Check Admin, Agents for any other agent named {join.Principal.AgentNamePrefix}-... that this principal registered, and retire it.";

    /// <summary>Exactly what the operator is about to save and sign: the serials and the lines added.</summary>
    public static string SignText(HostJoin join, long currentSerial, SiteSigner currentSigner) => string.Join("\n",
    [
        $"The fleet the bus holds is serial {currentSerial}. Its signature verifies, signed by {currentSigner.Principal} ({currentSigner.Fingerprint}).",
        "",
        $"The next fleet will be serial {currentSerial + 1}. It is that document with one change besides the serial, these lines added at the end:",
        FleetCompose.HostBlock(join.AgentName, join.AgentId).TrimEnd('\n'),
        "",
        "Every other byte is kept.",
        "",
        "The app cannot ask a hardware key to sign it on this PC: it found no key file here for any of the site's signers (Admin, Security says which key it would use). So you save it, sign it with the site's hardware key, and then publish it here.",
        "",
        "Save the new fleet document?"
    ]);

    /// <summary>What to do next, once the file is saved.</summary>
    public static string SavedText(string path, long serial, HostJoin join) => string.Join("\n",
    [
        $"Saved fleet serial {serial}, adding {join.AgentName}, as {path}",
        $"Saved the signer lines this PC holds as {SignersPath(path)}",
        "",
        "1. Sign it with the site's hardware key (touch and PIN). From a checkout of the project:",
        $"   pwsh -File worker-host\\tools\\sign-config.ps1 -File \"{path}\" -Signers \"{SignersPath(path)}\" -KeyFile $HOME\\.ssh\\<your hardware key file>",
        $"   It checks the result against those signer lines, the same ones this app checks against, and writes {System.IO.Path.GetFileName(path)}.sig beside the document.",
        "2. Then choose Publish a signed fleet document below and pick the saved file.",
        "",
        "The file is not secret. Nothing has been sent to the bus yet."
    ]);

    /// <summary>Where the held signer lines are saved, beside the document, for the signing tool to check against.</summary>
    public static string SignersPath(string documentPath) => documentPath + ".signers";

    /// <summary>The held lines as an allowed_signers file: one per line, LF, ending with a line feed.</summary>
    public static string SignersFile(IEnumerable<SiteSigner> held) => string.Concat(held.Select(signer => signer.Line + "\n"));

    /// <summary>Added to the publish question when the document is the one this app composed in this run.</summary>
    public static string ComposedNote(string change) => $"These are exactly the bytes this app composed: {change}.";

    public static AdminActionOption? Offered(IEnumerable<AdminActionOption> actions, string action) =>
        actions.FirstOrDefault(option => option.Action == action);
}
