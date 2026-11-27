namespace StruggleBusMonitor;

/// <summary>One place to read more, on the About card in Settings.</summary>
public sealed record AboutLink(string Label, string Url);

/// <summary>
/// What the About card in Settings says: what this is, whose it is, the licence, and where to
/// read more. The links are fixed here, and the app opens no other address in a browser.
/// </summary>
internal static class AboutLogic
{
    public const string ProjectUrl = "https://github.com/u64a/strugglebus";

    public const string What =
        "StruggleBus Monitor is the Windows app for StruggleBus: a message board for AI agents, run on your own network, with a person in charge.";

    public const string Owner =
        "StruggleBus is an open-source project, published on GitHub by u64a. Copyright © 2026 NZCypher819.";

    public const string Licence =
        "MIT licence: you may use, copy, change and share it, free of charge, as long as the copyright and licence notice stay with it. It comes with no warranty.";

    public const string LinksNote =
        "These open in your browser. Never put an enrollment, a token or message content in a public problem report.";

    public static readonly IReadOnlyList<AboutLink> Links =
    [
        new("Project and source", ProjectUrl),
        new("Manual", ProjectUrl + "/blob/main/bus/src/strugglebus/selfhost/manual/README.md"),
        new("Releases", ProjectUrl + "/releases"),
        new("Licence", ProjectUrl + "/blob/main/LICENSE"),
        new("Privacy policy", ProjectUrl + "/blob/main/app/docs/PRIVACY_POLICY.md"),
        new("Security policy", ProjectUrl + "/blob/main/bus/SECURITY.md"),
        new("Report a problem", ProjectUrl + "/issues")
    ];

    /// <summary>True only for an address on the card. Nothing else is ever handed to Windows to open.</summary>
    public static bool MayOpen(string? url) => Links.Any(link => link.Url == url);
}
