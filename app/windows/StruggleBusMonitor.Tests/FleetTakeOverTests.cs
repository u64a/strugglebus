using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;

namespace StruggleBusMonitor.Tests;

/// <summary>Which offered fleet may be published, and what the operator is shown.</summary>
public sealed class FleetTakeOverLogicTests
{
    private static readonly SiteSigner Signer = FleetPublishLogic.Signers(SshSignatureMaker.SignerLine(SshSignatureMaker.Key()))[0];

    private static CheckedOffer Good(string host, long serial, string extra = "") =>
        new(new FleetOffer("id-" + host, host, serial, [], "sig"), new SignedFleet(Encoding.UTF8.GetBytes($"serial = {serial}\n{extra}"), "sig", serial, Signer), null);

    private static CheckedOffer Bad(string host, string problem) => new(new FleetOffer("id-" + host, host, 4, [], "sig"), null, problem);

    private static string Refusal(IReadOnlyList<CheckedOffer> offers, params long[] reported) =>
        Assert.Throws<InvalidOperationException>(() => FleetTakeOverLogic.Choose(offers, reported)).Message;

    [Fact]
    public void TheFleetTheHostsRunNowIsChosenAndEveryHostThatOfferedItIsNamed()
    {
        var chosen = FleetTakeOverLogic.Choose([Good("host-a-host", 4), Good("host-b-host", 4)], [4, 4]);

        Assert.Equal(4, chosen.Fleet.Serial);
        Assert.Equal(["host-a-host", "host-b-host"], chosen.OfferedBy);
        Assert.Empty(chosen.NotUsed);
    }

    [Fact]
    public void AnOlderFleetIsNeverPublishedEvenThoughItsSignatureIsGood()
    {
        var chosen = FleetTakeOverLogic.Choose([Good("host-old-host", 3), Good("host-a-host", 4), Bad("host-x-host", "Not a signature.")], [4, 3]);

        Assert.Equal(["host-a-host"], chosen.OfferedBy);
        Assert.Equal(["host-old-host", "host-x-host"], chosen.NotUsed.Select(offer => offer.Offer.Agent));

        var onlyOld = Refusal([Good("host-old-host", 3)], 4);
        Assert.StartsWith("The hosts report that they run fleet serial 4, but no offered fleet is that serial", onlyOld);
        Assert.Contains("host-old-host offered serial 3", onlyOld);
        Assert.EndsWith("An older fleet is never published, even though its signature is good.", onlyOld);
    }

    [Fact]
    public void AFleetNewerThanAnyHostReportsIsNotPublishedEither()
    {
        Assert.Contains("host-a-host offered serial 9", Refusal([Good("host-a-host", 9)], 4));
    }

    [Fact]
    public void TwoDifferentFleetsAtTheSameSerialPublishNothing()
    {
        var message = Refusal([Good("host-a-host", 4), Good("host-b-host", 4, "owner = \"Mallory\"\n")], 4);

        Assert.StartsWith("Hosts offered different fleets that both say serial 4 and both verify.", message);
        Assert.Contains("host-a-host: SHA-256 ", message);
        Assert.Contains("host-b-host: SHA-256 ", message);
    }

    [Fact]
    public void WithNothingOfferedVerifiedOrReportedNothingIsPublished()
    {
        Assert.Equal(FleetTakeOverLogic.NoOffers, Refusal([], 4));
        Assert.Equal(FleetTakeOverLogic.NoneReported, Refusal([Good("host-a-host", 4)]));
        Assert.Equal(FleetTakeOverLogic.NoneReported, Refusal([Good("host-a-host", 4)], 0));

        var none = Refusal([Bad("host-a-host", "The signature does not verify."), Bad("host-b-host", "Not a hardware key.")], 4);
        Assert.StartsWith("None of the offered fleets passed the app's checks", none);
        Assert.Contains("host-a-host: The signature does not verify.", none);
        Assert.Contains("host-b-host: Not a hardware key.", none);
    }

    [Fact]
    public void TheReviewSaysWhatItIsWhatItListsWhoOfferedItAndWhatWasLeftOut()
    {
        var chosen = FleetTakeOverLogic.Choose([Good("host-a-host", 4), Good("host-old-host", 3), Bad("host-x-host", "Not a signature.")], [4]);
        IReadOnlyList<FleetAgent> listed = [new("coordinator", "coord-main", "1"), new("host", "host-a-host", "2"), new("host", "host-b-host", "3")];

        var text = FleetTakeOverLogic.ReviewText(chosen, listed);

        Assert.StartsWith("Publish the fleet your worker hosts already run, serial 4, to the bus?", text);
        Assert.Contains($"Signed by {Signer.Fingerprint}, one of this PC's site signers.", text);
        Assert.Contains("Offered by: host-a-host.", text);
        Assert.Contains("May task the hosts:  coord-main", text);
        Assert.Contains("Worker hosts:        host-a-host, host-b-host", text);
        Assert.Contains("Offers that are NOT published:", text);
        Assert.Contains("  host-old-host: serial 3, signature good, but not the serial the hosts run now", text);
        Assert.Contains("  host-x-host: refused. Not a signature.", text);
        Assert.Contains("nothing is re-signed", text);

        var bare = FleetTakeOverLogic.ReviewText(FleetTakeOverLogic.Choose([Good("host-a-host", 4)], [4]), []);
        Assert.Contains("May task the hosts:  (none)", bare);
        Assert.DoesNotContain("NOT published", bare);
        Assert.Contains("cannot read this fleet strictly", FleetTakeOverLogic.ReviewText(chosen, null));
    }

    [Fact]
    public void TheWordsForTheAuditReasonAndTheResultNameTheHostsAndTheSerial()
    {
        var chosen = FleetTakeOverLogic.Choose([Good("host-a-host", 4), Good("host-b-host", 4)], [4]);

        Assert.Equal("Taken over in the Windows app from host-a-host, host-b-host, unchanged: fleet serial 4", FleetTakeOverLogic.Reason(chosen));
        Assert.Equal("Publish the hosts' fleet, serial 4, to the bus", FleetTakeOverLogic.HelloPrompt(4));
        Assert.StartsWith("Published fleet serial 4 at ", FleetTakeOverLogic.ResultText(chosen, DateTimeOffset.UnixEpoch));

        var many = FleetTakeOverLogic.Choose([.. Enumerable.Range(0, 40).Select(number => Good($"host-number-{number:00}-host", 4))], [4]);
        Assert.Equal(256, FleetTakeOverLogic.Reason(many).Length);
    }
}

/// <summary>Taking over the hosts' fleet from the real window, with no file.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class FleetTakeOverWindowTests(StaWindowAdminFixture sta)
{
    private const string FleetRoute = "GET /api/mobile/site-documents/fleet";
    private const string PublishRoute = "POST /api/mobile/site-documents/fleet";
    private const string OffersRoute = "POST /api/mobile/admin/hosts/fleet-offers";
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly string Vectors = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");
    private static readonly byte[] Fleet = File.ReadAllBytes(Path.Combine(Vectors, "before.toml"));

    private const string Agents = """[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","name":"host-office1-host","description":"","host":"office1","last_seen_at":null}]""";

    private static string Status(long serial) => JsonSerializer.Serialize(new object[]
    {
        new
        {
            seq = 7, channel = "worker-hosts", agent_name = "host-office1-host", body = "host=office1", kind = "status",
            created_at = "2026-11-24T10:00:00Z", reply_to = (long?)null,
            metadata = new
            {
                sb_host_status = new
                {
                    v = 1, host = "office1", agent = "host-office1-host", version = "1.4.0", state = "online", account = "sbworker",
                    engines = Array.Empty<object>(), workers = new { busy = 0, max = 2 }, fleet = new { serial }, warnings = Array.Empty<string>()
                }
            }
        }
    });

    private static string Offer(string host, long serial, byte[] fleet, string? signature = null) => JsonSerializer.Serialize(new
    {
        agent_id = "id-" + host, agent = host, serial, fleet = Convert.ToBase64String(fleet), sig = signature ?? SshSignatureMaker.File(Key), received_at = "2030-01-02T03:04:05Z"
    });

    private static string Offers(bool held, params string[] offers) =>
        "{\"held\":" + (held ? "true" : "false") + ",\"offers\":[" + string.Join(",", offers) + "]}";

    /// <summary>Admin, Who may task the hosts, on a bus with no fleet whose one host reports the given serial.</summary>
    private static StaWindowAdminScene Open(string? offers, long reported = 5, bool withGrant = true)
    {
        var scene = new StaWindowAdminScene().Enroll(withGrant);
        try
        {
            var bus = scene.Bus;
            bus.AgentsJson = Agents;
            bus.On("GET /api/mobile/snapshot", request => StaWindowAdminBus.Ok(request.Query.Contains("agent=host-office1-host") ? Status(reported) : "[]"));
            bus.On("GET /api/mobile/admin/agents", _ => StaWindowAdminBus.Ok("[]"));
            bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok("[]"));
            bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok("[]"));
            bus.On(FleetRoute, _ => StaWindowAdminBus.Fail(404, "Not found."));
            if (offers is not null) bus.On(OffersRoute, _ => StaWindowAdminBus.Ok(offers));
            bus.On(PublishRoute, _ => StaWindowAdminBus.Ok(JsonSerializer.Serialize(new
            {
                name = "fleet", serial = 5, body = Convert.ToBase64String(Fleet), signature = "sig", signer_fingerprint = "SHA256:x", stored_at = "2030-01-02T03:04:05Z"
            })));
            scene.Open();
            var window = scene.Window;
            window.HostSigners.Text = SshSignatureMaker.SignerLine(Key);
            window.AdminNav.IsChecked = true;
            window.AdminTabFleet.IsChecked = true;
            StaWindowAdminScene.Until(() => window.FleetAccessSummary.Text.Length > 0, "the fleet card");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static void Press(StaWindowAdminScene scene)
    {
        scene.Window.FleetResultPanel.Visibility = Visibility.Collapsed;
        StaWindowAdminScene.ClickAndWait(scene.Window.FleetTakeOverButton);
        StaWindowAdminScene.Until(() => scene.Window.FleetResultPanel.Visibility == Visibility.Visible || scene.Notice.Length > 0 || scene.Platform.Confirmations.Count > 0, "the outcome");
    }

    [Fact]
    public void TheFleetTheHostsRunIsCheckedShownAndPublishedUnchangedWithNoFile() => sta.Run(() =>
    {
        using var scene = Open(Offers(false, Offer("host-office1-host", 5, Fleet)));
        Assert.Equal(Visibility.Visible, scene.Window.FleetStartPanel.Visibility);

        Press(scene);

        var asked = Assert.Single(scene.Platform.Confirmations);
        Assert.Equal(FleetTakeOverLogic.Caption, asked.Item2);
        Assert.Contains("serial 5, to the bus?", asked.Item1);
        Assert.Contains("May task the hosts:  coord-main", asked.Item1);
        Assert.Contains("Worker hosts:        host-office1-host", asked.Item1);
        Assert.Contains("Offered by: host-office1-host.", asked.Item1);
        Assert.Equal([(SshSignatureMaker.SignerLine(Key), "chris", "strugglebus-fleet", Fleet.Length)], scene.Platform.Verified);
        Assert.Contains(FleetTakeOverLogic.HelloPrompt(5), scene.Platform.HelloPrompts);

        var sent = JsonDocument.Parse(Assert.Single(scene.Bus.RequestsTo(PublishRoute)).Body).RootElement;
        Assert.Equal(5, sent.GetProperty("serial").GetInt64());
        Assert.Equal(Convert.ToBase64String(Fleet), sent.GetProperty("body").GetString());
        Assert.Equal(SshSignatureMaker.File(Key), sent.GetProperty("signature").GetString());
        Assert.StartsWith("Taken over in the Windows app from host-office1-host, unchanged", sent.GetProperty("reason").GetString());
        Assert.Empty(scene.Platform.Signed);
        Assert.StartsWith("Published fleet serial 5 at ", scene.Window.FleetResult.Text);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void AnOlderOfferIsNotPublishedAndSayingNoPublishesNothing() => sta.Run(() =>
    {
        using (var old = Open(Offers(false, Offer("host-office1-host", 5, Fleet)), reported: 6))
        {
            Press(old);
            Assert.StartsWith("The hosts report that they run fleet serial 6, but no offered fleet is that serial", old.Notice);
            Assert.Empty(old.Platform.Confirmations);
            Assert.Empty(old.Bus.RequestsTo(PublishRoute));
        }

        using var no = Open(Offers(false, Offer("host-office1-host", 5, Fleet)));
        no.Platform.ConfirmAnswer = false;
        Press(no);
        Assert.Single(no.Platform.Confirmations);
        Assert.DoesNotContain(no.Platform.HelloPrompts, prompt => prompt.StartsWith("Publish the hosts' fleet", StringComparison.Ordinal));
        Assert.Empty(no.Bus.RequestsTo(PublishRoute));
    });

    [Fact]
    public void AnOfferThatDoesNotVerifyOrIsNotAFleetIsNeverPublished() => sta.Run(() =>
    {
        using (var forged = Open(Offers(false, Offer("host-office1-host", 5, Fleet))))
        {
            forged.Platform.Verdict = SshVerdict.Bad;
            Press(forged);
            Assert.StartsWith("None of the offered fleets passed the app's checks", forged.Notice);
            Assert.Contains("host-office1-host: " + FleetPublishLogic.BadSignature, forged.Notice);
            Assert.Empty(forged.Bus.RequestsTo(PublishRoute));
        }

        using (var other = Open(Offers(false, Offer("host-office1-host", 5, Fleet, SshSignatureMaker.File(SshSignatureMaker.Key(seed: 9))))))
        {
            Press(other);
            Assert.Contains("host-office1-host: " + FleetPublishLogic.UnknownSigner, other.Notice);
            Assert.Empty(other.Platform.Verified);
        }

        using var junk = Open("""{"held":false,"offers":[{"agent_id":"x","agent":"host-office1-host","serial":5,"fleet":"not base64!","sig":"s","received_at":"x"}]}""");
        Press(junk);
        Assert.Contains("host-office1-host: The document is empty.", junk.Notice);
        Assert.Empty(junk.Bus.RequestsTo(PublishRoute));
    });

    [Fact]
    public void ABusThatCannotCarryOffersOrHoldsAFleetOrHasNoneSaysSo() => sta.Run(() =>
    {
        using (var old = Open(offers: null))
        {
            Press(old);
            Assert.Equal(FleetTakeOverLogic.BusTooOld, old.Notice);
        }

        using (var held = Open(Offers(true)))
        {
            Press(held);
            Assert.Equal(FleetTakeOverLogic.BusHoldsFleet, held.Notice);
        }

        using (var none = Open(Offers(false)))
        {
            Press(none);
            Assert.Equal(FleetTakeOverLogic.NoOffers, none.Notice);
        }

        using var noGrant = Open(Offers(false, Offer("host-office1-host", 5, Fleet)), withGrant: false);
        Press(noGrant);
        Assert.Equal(AdminFlow.GrantNeeded, noGrant.Notice);
        Assert.Empty(noGrant.Bus.RequestsTo(OffersRoute));
    });
}
