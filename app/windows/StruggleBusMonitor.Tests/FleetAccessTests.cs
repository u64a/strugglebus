using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>Who may be authorised, and what the operator is told before signing.</summary>
public sealed class FleetAccessLogicTests
{
    private static readonly DateTimeOffset Now = new(2030, 1, 2, 15, 0, 0, TimeSpan.Zero);

    private static ManagedAgent Agent(string id, string name, string state = "enabled") =>
        new(id, name, "writes the docs", "devbox", state, 1, Now.AddMinutes(-2), []);

    [Fact]
    public void OnlyEnabledAgentsThatAreNotHostsAndNotAlreadyListedAreOffered()
    {
        var fleet = new List<FleetAgent> { new("coordinator", "coord-main", "id-main"), new("host", "host-a-host", "id-host") };

        var choices = FleetAccessLogic.Choices(
            [
                Agent("id-docs", "coord-docs"), Agent("id-main", "coord-main"), Agent("id-x", "coord-blocked", "blocked"),
                Agent("id-r", "coord-retired", "retired"), Agent("id-h2", "host-b-host"), Agent("id-main", "renamed"), Agent("id-a", "alpha")
            ],
            fleet, Now);

        Assert.Equal(["alpha", "coord-docs"], choices.Select(choice => choice.Name));
        Assert.Equal("bare  ·  id id-b  ·  enabled  ·  never seen", FleetAccessLogic.Identity(new ManagedAgent("id-b", "bare", "", "", "enabled", 1, null, []), Now));
        Assert.Equal("coord-docs  ·  id id-docs  ·  enabled  ·  active 2m ago  ·  in its own words, not checked: runs on devbox; writes the docs", choices[1].Identity);
    }

    [Fact]
    public void ABusWithHundredsOfAgentsShowsOnlyTheFewThatMatchWhatWasTyped()
    {
        var all = Enumerable.Range(0, 900).Select(number => new AgentChoice { Id = $"id-{number}", Name = $"agent-{number:000}" })
            .Append(new AgentChoice { Id = "id-docs", Name = "coord-docs" })
            .Append(new AgentChoice { Id = "id-mydocs", Name = "my-docs-helper" })
            .Append(new AgentChoice { Id = "id-docsy", Name = "docs-writer" })
            .ToList();

        Assert.Empty(FleetAccessLogic.Matching(all, ""));
        Assert.Empty(FleetAccessLogic.Matching(all, "   "));
        Assert.Equal(["docs-writer", "coord-docs", "my-docs-helper"], FleetAccessLogic.Matching(all, " DOCS ").Select(choice => choice.Name));
        Assert.Equal(FleetAccessLogic.ShownMatches, FleetAccessLogic.Matching(all, "agent").Count);
        Assert.Equal("agent-000", FleetAccessLogic.Matching(all, "agent")[0].Name);

        Assert.Equal(FleetAccessLogic.SearchHint + " 903 enabled agents can be authorised.", FleetAccessLogic.SearchText(all, ""));
        Assert.Equal("Showing 8 of 900 matches. Keep typing to narrow them.", FleetAccessLogic.SearchText(all, "agent-"));
        Assert.Equal("3 matches. Choose one.", FleetAccessLogic.SearchText(all, "docs"));
        Assert.Equal("1 match. Choose one.", FleetAccessLogic.SearchText(all, "agent-042"));
        Assert.StartsWith("No enabled agent has \"zzz\" in its name.", FleetAccessLogic.SearchText(all, "zzz"));
    }

    [Fact]
    public void TheFleetIsListedWithWhatEachEntryIs()
    {
        var rows = FleetAccessLogic.Rows([new("coordinator", "coord-main", "1"), new("host", "host-a-host", "2"), new("host", null, "3")]);

        Assert.Equal(
            [("coord-main", "MAY TASK THE HOSTS", "Take this away"), ("host-a-host", "WORKER HOST", "Remove from the fleet")],
            rows.Select(row => (row.Name, row.KindLabel, row.RemoveLabel)));
    }

    private static readonly AgentChoice Chosen = new() { Id = "22222222-2222-4222-8222-222222222222", Name = "coord-docs", Identity = "coord-docs  ·  enabled" };

    [Fact]
    public void TheFormBecomesAFleetEntryWithTheAgentTakenFromTheBusNeverTyped()
    {
        var entry = FleetAccessLogic.Entry(new AccessForm(Chosen, " docs ", " https://github.com/acme/notes ", " docs-notes ", "https://github.com/acme/a\r\n\r\nhttps://github.com/acme/b\n"));

        Assert.Equal((Chosen.Name, Chosen.Id, "docs", "https://github.com/acme/notes", "docs-notes"),
            (entry.AgentName, entry.AgentId, entry.Project, entry.NotesRepo, entry.NotesChannel));
        Assert.Null(entry.DefaultEngine);
        Assert.Equal(["https://github.com/acme/a", "https://github.com/acme/b"], entry.Repos);
        Assert.Equal(FleetAccessLogic.ChooseAgent, Assert.Throws<InvalidOperationException>(() => FleetAccessLogic.Entry(new AccessForm(null, "", "", "", ""))).Message);
    }

    [Fact]
    public void TheConfirmationSaysAllHostsWhereAndCallsOutAWholeOwner()
    {
        var entry = new CoordinatorEntry(Chosen.Name, Chosen.Id, "docs", "https://github.com/acme/notes", "docs-notes", ["https://github.com/acme/", "https://github.com/acme/handbook"], "claude");

        var text = FleetAccessLogic.AuthoriseText(entry, Chosen, 2, ["https://github.com/acme/"]);

        Assert.StartsWith("Authorise coord-docs to task the worker hosts?", text);
        Assert.Contains("On the bus:  coord-docs  ·  enabled", text);
        Assert.Contains("will be able to have ALL 2 worker hosts in the fleet run agent workers, which run code, in:", text);
        Assert.Contains("  https://github.com/acme/   <<< WARNING: every repository under this, now and later", text);
        Assert.Contains("  https://github.com/acme/handbook\n", text);
        Assert.Contains(FleetAccessLogic.NotInstant, text);
        Assert.DoesNotContain("Engine:", text);
        Assert.Contains("chosen by each task, or by the host", text);
        Assert.Contains("ALL 1 worker host in the fleet", FleetAccessLogic.AuthoriseText(entry, Chosen, 1, []));
    }

    [Fact]
    public void RemovingSaysItIsNotInstantAndNamesTheLeversThatAre()
    {
        var coordinator = new FleetEntryRow { Kind = "coordinator", Name = "coord-docs" };
        var host = new FleetEntryRow { Kind = "host", Name = "host-a-host" };

        Assert.StartsWith("Take away coord-docs's authority to task the worker hosts?", FleetAccessLogic.RemoveText(coordinator));
        Assert.StartsWith("Remove worker host host-a-host from the fleet?", FleetAccessLogic.RemoveText(host));
        Assert.Contains("block or retire it on Admin, Agents, or freeze all agent access", FleetAccessLogic.RemoveText(coordinator));
        Assert.Equal("takes away coord-docs's authority to task the hosts", FleetAccessLogic.Removes(coordinator));
        Assert.Equal("removes worker host host-a-host", FleetAccessLogic.Removes(host));
        Assert.Equal("authorises coord-docs to task the hosts", FleetAccessLogic.Authorises("coord-docs"));
    }

    [Fact]
    public void ARefusalIsNeverADeadEnd()
    {
        Assert.EndsWith("Or ask for help on #humans.", FleetAccessLogic.RefusalText(new FleetRefusedException(FleetRefusal.HandEdited, "Hand edited.")));
        Assert.Equal("Not there.", FleetAccessLogic.RefusalText(new FleetRefusedException(FleetRefusal.NotListed, "Not there.")));
        Assert.Contains(@"-Signers ""C:\w\fleet.toml.signers""", FleetAccessLogic.SavedText(@"C:\w\fleet.toml", 8, "removes worker host x"));
    }
}

/// <summary>Authorising and removing from the real window, ending in a signed, published fleet.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class FleetAccessWindowTests(StaWindowAdminFixture sta)
{
    private const string FleetRoute = "GET /api/mobile/site-documents/fleet";
    private const string PublishRoute = "POST /api/mobile/site-documents/fleet";
    private const string KeyFile = @"C:\keys\id_ed25519_sk_test";
    private const string DocsId = "22222222-2222-4222-8222-222222222222";
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly string Vectors = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");

    private static byte[] Vector(string name) => File.ReadAllBytes(Path.Combine(Vectors, name));

    /// <summary>The shared vector as the app writes it: the same bytes without the one default_engine line the app no longer writes.</summary>
    private static byte[] WithoutEngine(byte[] vector)
    {
        var text = Encoding.UTF8.GetString(vector);
        var line = "default_engine = \"claude\"\n";
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(text, System.Text.RegularExpressions.Regex.Escape(line)));
        return Encoding.UTF8.GetBytes(text.Replace(line, string.Empty));
    }

    private static readonly string Managed =
        $$"""
        [{"id":"{{DocsId}}","name":"coord-docs","description":"writes the docs","host":"devbox","state":"enabled","credential_epoch":1,"last_seen_at":null,"actions":[]},
         {"id":"99999999-9999-4999-8999-999999999999","name":"coord-old","description":"","host":"","state":"blocked","credential_epoch":1,"last_seen_at":null,"actions":[]}]
        """;

    private static string Stored(byte[] body, long serial) => JsonSerializer.Serialize(new
    {
        name = "fleet", serial, body = Convert.ToBase64String(body), signature = SshSignatureMaker.File(Key), signer_fingerprint = "SHA256:x", stored_at = "2030-01-02T03:04:05Z"
    });

    /// <summary>Admin, Worker hosts, with a fleet on the bus and, unless told otherwise, a key the app can ask to sign.</summary>
    private static StaWindowAdminScene Open(string fleet, long serial, bool canSign = true, bool withGrant = true)
    {
        var scene = new StaWindowAdminScene().WithSettings(settings => settings.SignerKeyFiles[Convert.ToBase64String(Key)] = KeyFile).Enroll(withGrant);
        try
        {
            var bus = scene.Bus;
            bus.On("GET /api/mobile/admin/agents", _ => StaWindowAdminBus.Ok(Managed));
            bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok("[]"));
            bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok("[]"));
            bus.On(FleetRoute, _ => StaWindowAdminBus.Ok(Stored(Vector(fleet), serial)));
            bus.On(PublishRoute, _ => StaWindowAdminBus.Ok(Stored(Vector(fleet), serial + 1)));
            if (canSign) scene.Platform.KeyFiles.Add(KeyFile);
            scene.Platform.HardwareKey = _ => SshSignatureMaker.File(Key);
            scene.Open();
            var window = scene.Window;
            window.HostSigners.Text = SshSignatureMaker.SignerLine(Key);
            window.HostRemotes.Text = "https://github.com/acme/";
            window.AdminNav.IsChecked = true;
            window.AdminTabHosts.IsChecked = true;
            StaWindowAdminScene.Until(() => window.FleetAccessSummary.Text.Length > 0, "the fleet's entries");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static void FillDocs(MainWindow window)
    {
        window.AccessAgentSearch.Text = "docs";
        var choice = ((IEnumerable<AgentChoice>)window.AccessAgentsList.ItemsSource).Single();
        window.AccessAgent_Click(new Button { Tag = choice }, new RoutedEventArgs());
        window.AccessProject.Text = "docs";
        window.AccessNotesRepo.Text = "https://github.com/acme/docs-notes";
        window.AccessNotesChannel.Text = "docs-notes";
        window.AccessRepos.Text = "https://github.com/acme/handbook";
    }

    private static void Wait(StaWindowAdminScene scene) =>
        StaWindowAdminScene.Until(() => scene.Window.FleetResultPanel.Visibility == Visibility.Visible || scene.Notice.Length > 0, "the outcome");

    private static JsonElement Published(StaWindowAdminScene scene) => JsonDocument.Parse(Assert.Single(scene.Bus.RequestsTo(PublishRoute)).Body).RootElement;

    [Fact]
    public void TheFleetAndTheAgentsThatCanBeAuthorisedAreShown() => sta.Run(() =>
    {
        using var scene = Open("before.toml", 5);
        var window = scene.Window;

        // The Worker hosts tab shows the hosts; the fleet and the hardware keys each have a tab of their own.
        Assert.Equal(Visibility.Visible, window.AdminHostsPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminFleetAccessPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminAddHostPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminSecurityPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminReasonCard.Visibility);

        window.AdminTabSecurity.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.AdminSecurityPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminHostsPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminReasonCard.Visibility);

        window.AdminTabAddHost.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.AdminAddHostPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminSecurityPanel.Visibility);

        window.AdminTabFleet.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.AdminFleetAccessPanel.Visibility);
        Assert.Equal(Visibility.Visible, window.AdminFleetPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminAddHostPanel.Visibility);
        Assert.Equal(["coord-main", "host-office1-host"], ((IEnumerable<FleetEntryRow>)window.FleetEntriesList.ItemsSource).Select(row => row.Name));
        Assert.Equal("The fleet on the bus lists 1 agent(s) that may task the hosts and 1 worker host(s).", window.FleetAccessSummary.Text);
        Assert.StartsWith("No agent chosen", window.AccessAgentText.Text);

        // No agent is listed until the operator searches: a bus can hold hundreds.
        Assert.Empty((IEnumerable<AgentChoice>)window.AccessAgentsList.ItemsSource);
        Assert.Equal(FleetAccessLogic.SearchHint + " 1 enabled agent can be authorised.", window.AccessAgentSearchText.Text);

        window.AccessAgentSearch.Text = "DOC";
        Assert.Equal(["coord-docs"], ((IEnumerable<AgentChoice>)window.AccessAgentsList.ItemsSource).Select(choice => choice.Name));
        Assert.Equal("1 match. Choose one.", window.AccessAgentSearchText.Text);

        window.AccessAgentSearch.Text = "old";
        Assert.Empty((IEnumerable<AgentChoice>)window.AccessAgentsList.ItemsSource);
        Assert.StartsWith("No enabled agent has \"old\" in its name.", window.AccessAgentSearchText.Text);
    });

    [Fact]
    public void TheSitesRepositoryLocationsAreKeptAsSoonAsTheBoxIsLeft() => sta.Run(() =>
    {
        using var scene = Open("before.toml", 5);
        var window = scene.Window;
        Assert.Equal(string.Empty, AppSettings.Load().HostRemotes);

        window.HostRemotes_LostFocus(window.HostRemotes, new RoutedEventArgs());
        Assert.Equal("https://github.com/acme/", AppSettings.Load().HostRemotes);

        window.HostRemotes.Text = "https://github.com/acme/\nhttps://github.com/other/";
        window.HostRemotes_LostFocus(window.HostRemotes, new RoutedEventArgs());
        Assert.Equal(window.HostRemotes.Text, AppSettings.Load().HostRemotes);
    });

    [Fact]
    public void AuthorisingAnAgentEndsInASignedPublishedFleet() => sta.Run(() =>
    {
        using var scene = Open("before.toml", 5);
        var window = scene.Window;
        FillDocs(window);
        Assert.StartsWith("Chosen:  coord-docs", window.AccessAgentText.Text);

        StaWindowAdminScene.ClickAndWait(window.AccessAuthoriseButton);
        Wait(scene);

        Assert.Equal([FleetAccessLogic.AuthoriseCaption, "Sign the fleet"], scene.Platform.Confirmations.Select(asked => asked.Item2));
        Assert.Contains("ALL 1 worker host in the fleet", scene.Platform.Confirmations[0].Item1);
        Assert.Contains("Change:   authorises coord-docs to task the hosts", scene.Platform.Confirmations[1].Item1);
        // The app asks for no engine and writes none: hosts never use a coordinator's default to choose one.
        var expected = WithoutEngine(Vector("add-coordinator-after.toml"));
        Assert.DoesNotContain("default_engine = \"claude\"", Encoding.UTF8.GetString(expected));
        Assert.Equal(expected, Assert.Single(scene.Platform.Signed).Document);
        Assert.Equal("strugglebus-fleet", scene.Platform.Signed[0].Purpose);
        Assert.Equal(Convert.ToBase64String(expected), Published(scene).GetProperty("body").GetString());
        Assert.Equal(6, Published(scene).GetProperty("serial").GetInt64());
        Assert.Contains(FleetPublishLogic.HelloPrompt(6), scene.Platform.HelloPrompts);
        Assert.StartsWith("Published fleet serial 6 at ", window.FleetResult.Text);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void AWholeOwnerIsCalledOutBeforeSigningAndSayingNoSignsNothing() => sta.Run(() =>
    {
        using var scene = Open("before.toml", 5);
        FillDocs(scene.Window);
        scene.Window.AccessRepos.Text = "https://github.com/acme/";
        scene.Platform.ConfirmAnswer = false;

        StaWindowAdminScene.ClickAndWait(scene.Window.AccessAuthoriseButton);

        Assert.Contains("https://github.com/acme/   <<< WARNING", Assert.Single(scene.Platform.Confirmations).Item1);
        Assert.Empty(scene.Platform.Signed);
        Assert.Empty(scene.Bus.RequestsTo(PublishRoute));
    });

    [Fact]
    public void ValuesTheHostsWouldRefuseStopBeforeAnyQuestion() => sta.Run(() =>
    {
        using var scene = Open("before.toml", 5);
        var window = scene.Window;

        StaWindowAdminScene.ClickAndWait(window.AccessAuthoriseButton);
        Assert.Equal(FleetAccessLogic.ChooseAgent, scene.Notice);

        FillDocs(window);
        window.AccessRepos.Text = "https://github.com/other/repo";
        StaWindowAdminScene.ClickAndWait(window.AccessAuthoriseButton);
        Assert.Contains("outside the locations this site allows", scene.Notice);

        window.AccessRepos.Text = "https://github.com/acme/handbook";
        window.HostRemotes.Text = string.Empty;
        StaWindowAdminScene.ClickAndWait(window.AccessAuthoriseButton);
        Assert.Equal(FleetAccessLogic.NoRemotes, scene.Notice);
        Assert.Empty(scene.Platform.Confirmations);
        Assert.Empty(scene.Platform.Signed);
    });

    [Fact]
    public void RemovingACoordinatorOrAHostEndsInASignedPublishedFleet() => sta.Run(() =>
    {
        using (var scene = Open("two-each.toml", 7))
        {
            var row = ((IEnumerable<FleetEntryRow>)scene.Window.FleetEntriesList.ItemsSource).Single(entry => entry.Name == "coord-docs");
            scene.Window.FleetEntryRemove_Click(new Button { Tag = "not a row" }, new RoutedEventArgs());
            scene.Window.FleetEntryRemove_Click(new Button { Tag = row }, new RoutedEventArgs());
            Wait(scene);

            Assert.Equal([FleetAccessLogic.RemoveCaption, "Sign the fleet"], scene.Platform.Confirmations.Select(asked => asked.Item2));
            Assert.Contains(FleetAccessLogic.NotInstant, scene.Platform.Confirmations[0].Item1);
            Assert.Equal(Convert.ToBase64String(Vector("remove-coordinator-after.toml")), Published(scene).GetProperty("body").GetString());
            Assert.Contains("takes away coord-docs's authority", Published(scene).GetProperty("reason").GetString());
        }

        using var hosts = Open("two-each.toml", 7);
        var host = ((IEnumerable<FleetEntryRow>)hosts.Window.FleetEntriesList.ItemsSource).Single(entry => entry.Name == "host-office2-host");
        hosts.Window.FleetEntryRemove_Click(new Button { Tag = host }, new RoutedEventArgs());
        Wait(hosts);
        Assert.Equal(Convert.ToBase64String(Vector("remove-host-after.toml")), Published(hosts).GetProperty("body").GetString());
    });

    [Fact]
    public void TheOnlyCoordinatorCannotBeRemovedAndAHandEditedTableIsNotGuessedAt() => sta.Run(() =>
    {
        using (var scene = Open("before.toml", 5))
        {
            var only = ((IEnumerable<FleetEntryRow>)scene.Window.FleetEntriesList.ItemsSource).Single(entry => entry.Kind == "coordinator");
            scene.Window.FleetEntryRemove_Click(new Button { Tag = only }, new RoutedEventArgs());
            Wait(scene);
            Assert.StartsWith("This is the only agent authorised to task the hosts.", scene.Notice);
            Assert.Empty(scene.Platform.Confirmations);
        }

        using var edited = Open("hand-edited.toml", 7);
        var row = ((IEnumerable<FleetEntryRow>)edited.Window.FleetEntriesList.ItemsSource).Single(entry => entry.Name == "coord-docs");
        edited.Window.FleetEntryRemove_Click(new Button { Tag = row }, new RoutedEventArgs());
        Wait(edited);
        Assert.EndsWith("Or ask for help on #humans.", edited.Notice);
        Assert.Empty(edited.Platform.Signed);
    });

    [Fact]
    public void WithNoKeyToAskTheChangeIsSavedForSigningElsewhere() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("fleet-access-test-").FullName;
        try
        {
            using var scene = Open("before.toml", 5, canSign: false);
            scene.Platform.FleetSavePath = Path.Combine(folder, "fleet.toml");
            FillDocs(scene.Window);

            StaWindowAdminScene.ClickAndWait(scene.Window.AccessAuthoriseButton);
            Wait(scene);

            Assert.Equal(WithoutEngine(Vector("add-coordinator-after.toml")), File.ReadAllBytes(scene.Platform.FleetSavePath));
            Assert.True(File.Exists(scene.Platform.FleetSavePath + ".signers"));
            Assert.StartsWith("Saved fleet serial 6 (authorises coord-docs to task the hosts) as ", scene.Window.FleetResult.Text);
            Assert.Empty(scene.Bus.RequestsTo(PublishRoute));

            scene.Platform.FleetSavePath = null;
            scene.Window.FleetResultPanel.Visibility = Visibility.Collapsed;
            StaWindowAdminScene.ClickAndWait(scene.Window.AccessAuthoriseButton);
            Wait(scene);
            Assert.Equal(FleetJoinLogic.NothingChanged, scene.Window.FleetResult.Text);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void WithoutOperatorAccessNothingIsComposed() => sta.Run(() =>
    {
        using var scene = Open("before.toml", 5, withGrant: false);
        FillDocs(scene.Window);

        StaWindowAdminScene.ClickAndWait(scene.Window.AccessAuthoriseButton);
        Assert.Equal(AdminFlow.GrantNeeded, scene.Notice);

        var row = ((IEnumerable<FleetEntryRow>)scene.Window.FleetEntriesList.ItemsSource).First();
        scene.Window.FleetEntryRemove_Click(new Button { Tag = row }, new RoutedEventArgs());
        Wait(scene);
        Assert.Empty(scene.Platform.Verified);
        Assert.Empty(scene.Platform.Confirmations);
    });

    [Fact]
    public void ABusWithNoFleetOrOneOutsideTheStrictReadingShowsNothingToRemove() => sta.Run(() =>
    {
        using var scene = Open("unknown-table.toml", 5);

        Assert.Empty((IEnumerable<FleetEntryRow>)scene.Window.FleetEntriesList.ItemsSource);
        Assert.StartsWith("The bus holds no fleet yet, or one this app cannot read.", scene.Window.FleetAccessSummary.Text);

        StaWindowAdminScene.ClickAndWait(scene.Window.FleetAccessReload);
        Assert.Empty((IEnumerable<FleetEntryRow>)scene.Window.FleetEntriesList.ItemsSource);
    });
}
