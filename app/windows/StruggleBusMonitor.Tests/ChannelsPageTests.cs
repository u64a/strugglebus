using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>What the Channels page says about each channel.</summary>
public sealed class ChannelsPageLogicTests
{
    private static readonly DateTimeOffset Now = new(2030, 1, 2, 15, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ACardSaysWhatTheChannelIsForAndHowBusyItIs()
    {
        var card = ChannelsPageLogic.Card(new ChannelActivity("status", "  Agent status. No secrets.  ", 12, 3, Now.AddMinutes(-5)), Now);

        Assert.Equal(("status", "#status", "Agent status. No secrets."), (card.Name, card.Label, card.Purpose));
        Assert.StartsWith("12 messages  ·  3 agents listening  ·  last message ", card.Figures);
        Assert.True(card.HasPurpose && card.HasFigures);
    }

    [Fact]
    public void OneOfSomethingIsNotPluralAndAQuietChannelSaysSo()
    {
        Assert.Equal(
            "1 message  ·  1 agent listening  ·  nothing posted yet",
            ChannelsPageLogic.Figures(new ChannelActivity("c", "", 1, 1, null), Now));
        Assert.Equal(
            "0 messages  ·  0 agents listening  ·  nothing posted yet",
            ChannelsPageLogic.Figures(new ChannelActivity("c", "", 0, 0, null), Now));
    }

    [Fact]
    public void ABusThatGivesNoFiguresShowsNoneAndTheSummarySaysWhy()
    {
        var channels = ChannelsPageLogic.WithoutFigures([new BusChannel("1", "status", "Agent status"), new BusChannel("2", "help", "")]);
        var cards = channels.Select(channel => ChannelsPageLogic.Card(channel, Now)).ToList();

        Assert.Equal(["status", "help"], cards.Select(card => card.Name));
        Assert.All(cards, card => Assert.False(card.HasFigures));
        Assert.False(cards[1].HasPurpose);
        Assert.Equal("2 channels. " + ChannelsPageLogic.NoFigures, ChannelsPageLogic.Summary(cards, withFigures: false));
        Assert.Equal("2 channels.", ChannelsPageLogic.Summary(cards, withFigures: true));
        Assert.Equal("1 channel.", ChannelsPageLogic.Summary(cards.Take(1).ToList(), withFigures: true));
        Assert.Equal("This bus has no channels yet.", ChannelsPageLogic.Summary([], withFigures: true));
    }

    [Fact]
    public void ThePageAsksTheBusAgainAfterAMinute()
    {
        Assert.True(ChannelsPageLogic.IsStale(null, Now));
        Assert.False(ChannelsPageLogic.IsStale(Now.AddSeconds(-59), Now));
        Assert.True(ChannelsPageLogic.IsStale(Now.AddSeconds(-60), Now));
    }
}

/// <summary>The Channels page in the real window.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class ChannelsWindowTests(StaWindowAdminFixture sta)
{
    private const string ActivityRoute = "GET /api/mobile/channels/activity";
    private const string Activity = """
        [{"name":"status","purpose":"Agent status. No secrets.","created_at":"2030-01-01T00:00:00Z","message_count":12,"subscriber_count":3,"last_activity_at":"2030-01-02T00:00:00Z"},
         {"name":"general","purpose":"Everything","created_at":"2030-01-01T00:00:00Z","message_count":0,"subscriber_count":1,"last_activity_at":null}]
        """;

    private static StaWindowAdminScene OpenChannels(bool modernBus = true)
    {
        var scene = new StaWindowAdminScene().Enroll();
        try
        {
            if (modernBus) scene.Bus.On(ActivityRoute, _ => StaWindowAdminBus.Ok(Activity));
            scene.Open();
            scene.Window.ChannelsNav.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.ChannelsSummary.Text.Length > 0, "the channels");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static List<ChannelCard> Cards(MainWindow window) => ((IEnumerable<ChannelCard>)window.ChannelsList.ItemsSource).ToList();

    [Fact]
    public void TheChannelsPageListsEachChannelWithItsPurposeAndFigures() => sta.Run(() =>
    {
        using var scene = OpenChannels();
        var window = scene.Window;

        Assert.Equal(Visibility.Visible, window.ChannelsPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.MonitorPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.HostsPage.Visibility);
        var cards = Cards(window);
        Assert.Equal(["general", "status"], cards.Select(card => card.Name));
        Assert.Equal("Agent status. No secrets.", cards[1].Purpose);
        Assert.StartsWith("12 messages  ·  3 agents listening  ·  last message ", cards[1].Figures);
        Assert.Equal("0 messages  ·  1 agent listening  ·  nothing posted yet", cards[0].Figures);
        Assert.Equal("2 channels.", window.ChannelsSummary.Text);
        Assert.Equal(string.Empty, scene.Notice);

        StaWindowAdminScene.ClickAndWait(window.ChannelsReload);
        Assert.Equal(2, scene.Bus.RequestsTo(ActivityRoute).Count);

        // Coming back within the minute does not ask again.
        window.MonitorNav.IsChecked = true;
        window.ChannelsNav.IsChecked = true;
        Assert.Equal(2, scene.Bus.RequestsTo(ActivityRoute).Count);
    });

    [Fact]
    public void AnOlderBusShowsNamesAndPurposesAndSaysTheCountsNeedANewerOne() => sta.Run(() =>
    {
        using var scene = OpenChannels(modernBus: false);
        var card = Assert.Single(Cards(scene.Window));

        Assert.Equal(("general", "Everything", false), (card.Name, card.Purpose, card.HasFigures));
        Assert.Equal("1 channel. " + ChannelsPageLogic.NoFigures, scene.Window.ChannelsSummary.Text);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void ShowInMonitorOpensMonitorOnThatChannelAlone() => sta.Run(() =>
    {
        using var scene = OpenChannels();
        var window = scene.Window;

        window.ChannelShow_Click(new Button { Tag = "not a channel" }, new RoutedEventArgs());
        Assert.Equal(Visibility.Visible, window.ChannelsPage.Visibility);
        window.ChannelShow_Click(new Button { Tag = Cards(window)[0] }, new RoutedEventArgs());

        Assert.Equal(Visibility.Visible, window.MonitorPage.Visibility);
        Assert.Equal("general", (window.ChannelFilter.SelectedItem as ChannelFilterOption)?.Name);
    });

    [Fact]
    public void AnUnenrolledPcCannotOpenChannels() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();

        Assert.False(scene.Window.ChannelsNav.IsEnabled);
    });
}
