using System.Security.Cryptography;

namespace StruggleBusMonitor;

/// <summary>The fleet one worker host says it accepts, as the bus carried it. Nothing in it is trusted until checked.</summary>
internal sealed record FleetOffer(string AgentId, string Agent, long Serial, byte[] Fleet, string Signature);

/// <summary>An offer after the app's own checks: the verified fleet, or why it was refused.</summary>
internal sealed record CheckedOffer(FleetOffer Offer, SignedFleet? Fleet, string? Problem);

/// <summary>The one fleet the app will publish, who offered it, and every other offer, for the operator to see.</summary>
internal sealed record TakeOver(SignedFleet Fleet, IReadOnlyList<string> OfferedBy, IReadOnlyList<CheckedOffer> NotUsed);

/// <summary>
/// Taking over a fleet the worker hosts already run, with no file. A site that kept its fleet in a
/// repository has hosts running a signed fleet the bus never held. Each host offers what it
/// accepts; the app checks an offer exactly as it checks any signed fleet, and publishes it
/// unchanged. Nothing is re-signed.
///
/// The bus and the hosts are only carriers here. A host or bus that lied would hand over
/// something whose signature does not verify against the keys this PC holds. An older fleet that
/// is validly signed would verify, though, so one more rule applies: the fleet published must be
/// the serial the hosts report they run now, and no other.
/// </summary>
internal static class FleetTakeOverLogic
{
    public const string Caption = "Take over the hosts' fleet";

    public const string BusTooOld =
        "This bus cannot carry the hosts' fleet to the app yet. That needs StruggleBus 0.2.75 or newer.";

    public const string BusHoldsFleet = "The bus already holds a fleet, so there is nothing to take over. Change that one here.";

    public const string NoOffers =
        "No worker host has offered its fleet yet. A host offers it when it reads its fleet from the bus, finds none there, and runs a worker-host release that knows how; that happens at its next fleet check. Try again in a few minutes.";

    public const string NoneReported =
        "No worker host reports which fleet serial it runs, so the app cannot tell whether an offered fleet is the current one. Nothing is published.";

    /// <summary>
    /// The fleet to publish: the verified offer whose signed serial is the highest any host
    /// reports. Throws, in words, when there is none or when two different fleets claim it.
    /// </summary>
    public static TakeOver Choose(IReadOnlyList<CheckedOffer> offers, IEnumerable<long> reported)
    {
        var verified = Verified(offers);
        var running = reported.DefaultIfEmpty(0).Max();
        if (running <= 0) throw new InvalidOperationException(NoneReported);

        var current = Current(verified, running);
        return new TakeOver(current[0].Fleet!, current.Select(offer => offer.Offer.Agent).ToList(), offers.Except(current).ToList());
    }

    /// <summary>The offers that passed the app's checks. Throws when there are no offers, or none passed.</summary>
    private static List<CheckedOffer> Verified(IReadOnlyList<CheckedOffer> offers)
    {
        if (offers.Count == 0) throw new InvalidOperationException(NoOffers);
        var verified = offers.Where(offer => offer.Fleet is not null).ToList();
        return verified.Count > 0 ? verified : throw new InvalidOperationException(NoneVerified(offers));
    }

    /// <summary>The verified offers at the serial the hosts run, which must all be the same bytes.</summary>
    private static List<CheckedOffer> Current(List<CheckedOffer> verified, long running)
    {
        var current = verified.Where(offer => offer.Fleet!.Serial == running).ToList();
        if (current.Count == 0) throw new InvalidOperationException(NoneCurrent(verified, running));
        return current.Select(offer => Hash(offer.Fleet!.Body)).Distinct().Count() == 1
            ? current
            : throw new InvalidOperationException(Disagree(current, running));
    }

    private static string Hash(byte[] body) => Convert.ToHexStringLower(SHA256.HashData(body));

    private static string NoneVerified(IReadOnlyList<CheckedOffer> offers) =>
        "None of the offered fleets passed the app's checks, so nothing is published:\n" +
        string.Join("\n", offers.Select(offer => $"  {offer.Offer.Agent}: {offer.Problem}"));

    private static string NoneCurrent(IReadOnlyList<CheckedOffer> verified, long running) =>
        $"The hosts report that they run fleet serial {running}, but no offered fleet is that serial, so none is published:\n" +
        string.Join("\n", verified.Select(offer => $"  {offer.Offer.Agent} offered serial {offer.Fleet!.Serial}")) +
        "\nAn older fleet is never published, even though its signature is good.";

    private static string Disagree(IReadOnlyList<CheckedOffer> current, long running) =>
        $"Hosts offered different fleets that both say serial {running} and both verify. They cannot both be right, so nothing is published:\n" +
        string.Join("\n", current.Select(offer => $"  {offer.Offer.Agent}: SHA-256 {FleetSignLogic.ShortHash(offer.Fleet!.Body)} ..., {offer.Fleet.Body.Length:N0} bytes")) +
        "\nFind out which is the real one before going on.";

    /// <summary>What the operator reads before the fleet is published: what it is, what it lists, who offered it, and what was left out.</summary>
    public static string ReviewText(TakeOver chosen, IReadOnlyList<FleetAgent>? listed) => string.Join("\n",
    [
        $"Publish the fleet your worker hosts already run, serial {chosen.Fleet.Serial}, to the bus?",
        "",
        $"Signed by {chosen.Fleet.Signer.Fingerprint}, one of this PC's site signers. The signature verifies for these exact {chosen.Fleet.Body.Length:N0} bytes (SHA-256 {FleetSignLogic.ShortHash(chosen.Fleet.Body)} ...).",
        $"Offered by: {string.Join(", ", chosen.OfferedBy)}.",
        "",
        .. Contents(listed),
        .. NotUsedLines(chosen.NotUsed),
        "",
        "It is published exactly as it is; nothing is re-signed. From then on the fleet is changed here in the app."
    ]);

    private static IEnumerable<string> Contents(IReadOnlyList<FleetAgent>? listed)
    {
        if (listed is null) return ["The app cannot read this fleet strictly, so it cannot list what is in it or change it afterwards. It can still be published as it is."];
        return
        [
            "May task the hosts:  " + Names(listed, "coordinator"),
            "Worker hosts:        " + Names(listed, "host")
        ];
    }

    private static string Names(IReadOnlyList<FleetAgent> listed, string kind)
    {
        var names = listed.Where(agent => agent.Kind == kind).Select(agent => agent.Name ?? "(unnamed)").ToList();
        return names.Count == 0 ? "(none)" : string.Join(", ", names);
    }

    private static IEnumerable<string> NotUsedLines(IReadOnlyList<CheckedOffer> notUsed)
    {
        if (notUsed.Count == 0) return [];
        return ["", "Offers that are NOT published:", .. notUsed.Select(NotUsedLine)];
    }

    private static string NotUsedLine(CheckedOffer offer) => offer.Fleet is { } fleet
        ? $"  {offer.Offer.Agent}: serial {fleet.Serial}, signature good, but not the serial the hosts run now"
        : $"  {offer.Offer.Agent}: refused. {offer.Problem}";

    public static string HelloPrompt(long serial) => $"Publish the hosts' fleet, serial {serial}, to the bus";

    public static string Reason(TakeOver chosen)
    {
        var reason = $"Taken over in the Windows app from {string.Join(", ", chosen.OfferedBy)}, unchanged: fleet serial {chosen.Fleet.Serial}";
        return reason.Length > 256 ? reason[..256] : reason;
    }

    public static string ResultText(TakeOver chosen, DateTimeOffset storedAt) =>
        $"Published fleet serial {chosen.Fleet.Serial} at {storedAt.ToLocalTime():HH:mm:ss}, exactly as {string.Join(", ", chosen.OfferedBy)} offered it. " +
        "The bus now holds your site's fleet, and you can change it here.";
}
