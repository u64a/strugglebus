using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>The words of step 10: the comparison, the refusal and what is signed.</summary>
public sealed class FleetJoinLogicTests
{
    private const string AgentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private const string Request = "11111111-2222-4333-8444-555555555555";

    private static HostJoin Join(string? from = "192.168.1.20", HostStatus? status = null, params string[] actions) => new(
        AgentId, "host-office2-host",
        new ManagedServicePrincipal("sp1", "host-office2", "host-office2", "enabled", 3, actions.Select(action => new AdminActionOption(action, "effect")).ToList(), Request, from),
        status);

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.4.4", true)]
    [InlineData("169.254.9.9", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("::ffff:192.168.1.5", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("::ffff:8.8.8.8", false)]
    [InlineData("not an address", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void OnlyAnAddressOnALocalNetworkCountsAsLocal(string? address, bool local) =>
        Assert.Equal(local, FleetJoinLogic.IsLocalAddress(address));

    [Fact]
    public void TheComparisonShowsTheCodeWhereItWasRedeemedAndWhatTheHostSaysOfItself()
    {
        var status = new HostStatus("OFFICE2", "host-office2-host", "2026.11.28", "needs-fleet", "sbhost", [new HostEngine("claude", "1", true)], 0, 2, 0, 0, null, "", ["not-dedicated"]);

        var text = FleetJoinLogic.CompareText(Join(status: status));

        Assert.Contains($"Confirmation code:  {HostsLogic.ConfirmationCode(AgentId, Request)}", text);
        Assert.Contains("Redeemed from:      192.168.1.20\n", text);
        Assert.Contains("Service principal:  host-office2", text);
        Assert.Contains("  PC name:          OFFICE2", text);
        Assert.Contains("  Windows account:  sbhost", text);
        Assert.Contains("  Engines:          claude", text);
        Assert.Contains("  Warnings:         not-dedicated", text);
        Assert.Contains("Is the code above exactly the code the installer printed?", text);
    }

    [Fact]
    public void AnAddressFromOutsideIsCalledOutAndMissingFactsAreSaidToBeMissing()
    {
        Assert.Contains("8.8.8.8   <<< WARNING: not an address on a local network", FleetJoinLogic.CompareText(Join(from: "8.8.8.8")));
        Assert.Contains("the bus did not record an address", FleetJoinLogic.CompareText(Join(from: null)));
        Assert.Contains("The host has not reported its status yet.", FleetJoinLogic.CompareText(Join()));

        var silent = new HostStatus("", "a", "v", "needs-fleet", "", [], 0, 0, 0, 0, null, "", []);
        Assert.Contains("  PC name:          (not reported)", FleetJoinLogic.CompareText(Join(status: silent)));
    }

    [Fact]
    public void TheRefusalNamesBothThingsItWillEndAndSaysTheFleetIsNotChanged()
    {
        var join = Join();

        var text = FleetJoinLogic.NoMatchText(join);
        Assert.Contains("revokes the service principal host-office2 and retires the agent host-office2-host", text);
        Assert.Contains("The fleet is not changed.", text);
        Assert.Equal("Revoke host-office2 and retire host-office2-host", FleetJoinLogic.RetireHelloPrompt(join));
        Assert.Contains("did not match the installer's", FleetJoinLogic.RetireReason(join));
        Assert.Contains("host-office2: revoked. Agent host-office2-host: retired.", FleetJoinLogic.RetiredText(join, true, true));
        Assert.Contains("NOT revoked", FleetJoinLogic.RetiredText(join, false, true));
        Assert.Contains("NOT retired", FleetJoinLogic.RetiredText(join, true, false));
        Assert.EndsWith(
            "Only the host agent was retired. Check Admin, Agents for any other agent named host-office2-... that this principal registered, and retire it.",
            FleetJoinLogic.RetiredText(join, true, true));
    }

    [Fact]
    public void WhatIsSignedIsShownExactlyAndTheNextStepsAreSpelledOut()
    {
        var signer = FleetPublishLogic.Signers(SshSignatureMaker.SignerLine(SshSignatureMaker.Key()))[0];

        var sign = FleetJoinLogic.SignText(Join(), 5, signer);
        Assert.Contains("The fleet the bus holds is serial 5.", sign);
        Assert.Contains("The next fleet will be serial 6.", sign);
        Assert.Contains($"[[host]]\nagent_name = \"host-office2-host\"\nagent_id   = \"{AgentId}\"", sign);
        Assert.Contains("The app does not sign it", sign);

        var saved = FleetJoinLogic.SavedText(@"C:\work\fleet.toml", 6, Join());
        Assert.Contains(@"sign-config.ps1 -File ""C:\work\fleet.toml"" -Signers ""C:\work\fleet.toml.signers"" -KeyFile", saved);
        Assert.Equal(signer.Line + "\n", FleetJoinLogic.SignersFile([signer]));
        Assert.Contains("and writes fleet.toml.sig beside the document.", saved);
        Assert.Contains("Nothing has been sent to the bus yet.", saved);
    }

    [Fact]
    public void AnActionIsUsedOnlyWhenTheBusOffersIt()
    {
        Assert.NotNull(FleetJoinLogic.Offered(Join(actions: ["block", "revoke"]).Principal.Actions, "revoke"));
        Assert.Null(FleetJoinLogic.Offered(Join(actions: ["block"]).Principal.Actions, "revoke"));
    }
}

/// <summary>Step 10 in the real window: compare, then compose and save, or refuse.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class FleetJoinWindowTests(StaWindowAdminFixture sta)
{
    private const string AgentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private const string FleetRoute = "GET /api/mobile/site-documents/fleet";
    private const string PublishRoute = "POST /api/mobile/site-documents/fleet";
    private const string RevokeRoute = "POST /api/mobile/admin/service-principals/sp1/control";
    private const string RetireRoute = $"POST /api/mobile/admin/agents/{AgentId}/control";
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly string Vectors = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");

    private static readonly string Agents =
        $$"""[{"id":"{{AgentId}}","name":"host-office2-host","description":"","host":"office2","last_seen_at":null}]""";

    private static readonly string Principals =
        """[{"id":"sp1","name":"host-office2","agent_name_prefix":"host-office2","status":"enabled","version":3,"actions":[{"action":"block","effect":"e"},{"action":"revoke","effect":"e"}],"host_redeem_request_id":"11111111-2222-4333-8444-555555555555","host_redeemed_from":"192.168.1.20"}]""";

    private static readonly string Managed =
        $$"""[{"id":"{{AgentId}}","name":"host-office2-host","description":"","host":"office2","state":"enabled","credential_epoch":7,"last_seen_at":null,"actions":[{"action":"block","effect":"e"},{"action":"retire","effect":"e"}]}]""";

    private const string Applied = """{"applied":true,"detail":"Done.","target_label":"x","state":"gone","secret":null}""";

    private static string Stored(byte[] body, long serial, string signature) => JsonSerializer.Serialize(new
    {
        name = "fleet", serial, body = Convert.ToBase64String(body), signature, signer_fingerprint = "SHA256:x", stored_at = "2030-01-02T03:04:05Z"
    });

    /// <summary>Admin, Worker hosts, with one host that joined with a code and a fleet on the bus.</summary>
    private sealed class Joining : IDisposable
    {
        private readonly string _folder = Directory.CreateTempSubdirectory("fleet-join-test-").FullName;
        public StaWindowAdminScene Scene { get; }
        public string Saved => Path.Combine(_folder, "fleet.toml");

        public Joining(bool withGrant = true, bool fleetOnBus = true, long busSerial = 5)
        {
            Scene = new StaWindowAdminScene().Enroll(withGrant);
            var bus = Scene.Bus;
            bus.AgentsJson = Agents;
            bus.On("GET /api/mobile/admin/agents", _ => StaWindowAdminBus.Ok(Managed));
            bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok("[]"));
            bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok(Principals));
            bus.On(FleetRoute, _ => fleetOnBus
                ? StaWindowAdminBus.Ok(Stored(File.ReadAllBytes(Path.Combine(Vectors, "before.toml")), busSerial, SshSignatureMaker.File(Key)))
                : StaWindowAdminBus.Fail(404, "Not found."));
            bus.On(PublishRoute, _ => StaWindowAdminBus.Ok(Stored([], 6, "sig")));
            bus.On(RevokeRoute, _ => StaWindowAdminBus.Ok(Applied));
            bus.On(RetireRoute, _ => StaWindowAdminBus.Ok(Applied));
            Scene.Platform.FleetSavePath = Saved;
            Scene.Open();
            Scene.Window.HostSigners.Text = SshSignatureMaker.SignerLine(Key);
            Scene.Window.AdminNav.IsChecked = true;
            Scene.Window.AdminTabHosts.IsChecked = true;
            StaWindowAdminScene.Until(() => Scene.Window.AdminHostsSummary.Text.Length > 0, "the worker hosts");
        }

        public HostRow Row => ((IEnumerable<HostRow>)Scene.Window.AdminHostList.ItemsSource).Single();

        /// <summary>Presses the row's button and waits until the result, a notice, or the given condition shows.</summary>
        public void Press(Func<bool>? done = null)
        {
            var window = Scene.Window;
            window.FleetResultPanel.Visibility = Visibility.Collapsed;
            window.HostJoin_Click(new Button { Tag = Row }, new RoutedEventArgs());
            StaWindowAdminScene.Until(
                () => done?.Invoke() ?? (window.FleetResultPanel.Visibility == Visibility.Visible || Scene.Notice.Length > 0), "the outcome of the comparison");
        }

        public void Dispose()
        {
            Scene.Dispose();
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Fact]
    public void AMatchComposesTheNextFleetAndSavesItForSigningWithoutSendingAnything() => sta.Run(() =>
    {
        using var joining = new Joining();
        var scene = joining.Scene;
        Assert.True(joining.Row.CanJoinFleet);

        joining.Press();

        Assert.Equal(File.ReadAllBytes(Path.Combine(Vectors, "after.toml")), File.ReadAllBytes(joining.Saved));
        Assert.Equal([FleetJoinLogic.CompareCaption, FleetJoinLogic.SignCaption], scene.Platform.Confirmations.Select(asked => asked.Item2));
        Assert.Contains("The next fleet will be serial 6.", scene.Platform.Confirmations[1].Item1);
        Assert.StartsWith("Saved fleet serial 6, adding host-office2-host, as ", scene.Window.FleetResult.Text);
        Assert.Equal(SshSignatureMaker.SignerLine(Key) + "\n", File.ReadAllText(joining.Saved + ".signers"));
        Assert.Empty(scene.Bus.RequestsTo(PublishRoute));
        Assert.Empty(scene.Bus.RequestsTo(RevokeRoute));
        Assert.Single(scene.Platform.Verified);
        Assert.Equal(string.Empty, scene.Notice);

        // Publishing those same bytes, once signed, says they are the ones composed here.
        File.WriteAllText(joining.Saved + ".sig", SshSignatureMaker.File(Key));
        scene.Platform.FleetFilePath = joining.Saved;
        StaWindowAdminScene.ClickAndWait(scene.Window.FleetPublishButton);
        Assert.Contains(FleetJoinLogic.ComposedNote("host-office2-host"), scene.Platform.Confirmations[^1].Item1);
        Assert.Single(scene.Bus.RequestsTo(PublishRoute));
    });

    [Fact]
    public void StoppingAtWhatWillBeSignedOrAtTheSaveSavesNothing() => sta.Run(() =>
    {
        using var joining = new Joining();
        joining.Scene.Platform.ConfirmAnswers.Enqueue(true);
        joining.Scene.Platform.ConfirmAnswers.Enqueue(false);

        joining.Press();
        Assert.Equal(FleetJoinLogic.NothingChanged, joining.Scene.Window.FleetResult.Text);
        Assert.False(File.Exists(joining.Saved));

        joining.Scene.Platform.FleetSavePath = null;
        joining.Press();
        Assert.Equal(FleetJoinLogic.NothingChanged, joining.Scene.Window.FleetResult.Text);
    });

    [Fact]
    public void ANoThenANoChangesNothing() => sta.Run(() =>
    {
        using var joining = new Joining();
        joining.Scene.Platform.ConfirmAnswer = false;

        joining.Press();

        Assert.Equal([FleetJoinLogic.CompareCaption, FleetJoinLogic.NoMatchCaption], joining.Scene.Platform.Confirmations.Select(asked => asked.Item2));
        Assert.Equal(FleetJoinLogic.NothingChanged, joining.Scene.Window.FleetResult.Text);
        Assert.Empty(joining.Scene.Bus.RequestsTo(RevokeRoute));
        Assert.Empty(joining.Scene.Bus.RequestsTo(RetireRoute));
        Assert.Empty(joining.Scene.Bus.RequestsTo(FleetRoute));
    });

    [Fact]
    public void ANoThenAYesRevokesThePrincipalAndRetiresTheAgentAndNeverTouchesTheFleet() => sta.Run(() =>
    {
        using var joining = new Joining();
        var scene = joining.Scene;
        scene.Platform.ConfirmAnswers.Enqueue(false);
        scene.Platform.ConfirmAnswers.Enqueue(true);

        joining.Press();

        var revoke = JsonDocument.Parse(Assert.Single(scene.Bus.RequestsTo(RevokeRoute)).Body).RootElement;
        Assert.Equal(("revoke", "host-office2", 3), (revoke.GetProperty("action").GetString(), revoke.GetProperty("expected_name").GetString(), revoke.GetProperty("expected_version").GetInt32()));
        var retire = JsonDocument.Parse(Assert.Single(scene.Bus.RequestsTo(RetireRoute)).Body).RootElement;
        Assert.Equal(("retire", "host-office2-host", 7), (retire.GetProperty("action").GetString(), retire.GetProperty("expected_name").GetString(), retire.GetProperty("expected_credential_epoch").GetInt32()));
        Assert.Contains("did not match the installer's", retire.GetProperty("reason").GetString());
        Assert.Contains("Revoke host-office2 and retire host-office2-host", scene.Platform.HelloPrompts);
        Assert.Contains("host-office2: revoked. Agent host-office2-host: retired.", scene.Window.FleetResult.Text);
        Assert.Contains("Only the host agent was retired.", scene.Window.FleetResult.Text);
        Assert.Empty(scene.Bus.RequestsTo(FleetRoute));
        Assert.Empty(scene.Bus.RequestsTo(PublishRoute));
        Assert.False(File.Exists(joining.Saved));
    });

    [Fact]
    public void WithNoFleetOnTheBusOrOneThatDoesNotVerifyNothingIsComposed() => sta.Run(() =>
    {
        using (var none = new Joining(fleetOnBus: false))
        {
            none.Press();
            Assert.Equal(FleetJoinLogic.NoFleetYet, none.Scene.Notice);
        }

        using (var bad = new Joining())
        {
            bad.Scene.Platform.Verdict = SshVerdict.Bad;
            bad.Press();
            Assert.Equal("The fleet the bus holds: " + FleetPublishLogic.BadSignature, bad.Scene.Notice);
            Assert.False(File.Exists(bad.Saved));
        }

        using var mismatch = new Joining(busSerial: 4);
        mismatch.Press();
        Assert.Contains("The bus says its fleet is serial 4, but the document it holds says serial 5.", mismatch.Scene.Notice);
    });

    [Fact]
    public void WithoutOperatorAccessOrOnAnotherKindOfRowNothingIsAsked() => sta.Run(() =>
    {
        using var joining = new Joining(withGrant: false);

        joining.Scene.Window.HostJoin_Click(new Button { Tag = "not a row" }, new RoutedEventArgs());
        joining.Press();

        Assert.Empty(joining.Scene.Platform.Confirmations);
        Assert.Equal(AdminFlow.GrantNeeded, joining.Scene.Notice);
    });
}
