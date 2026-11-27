using System.Windows;

namespace StruggleBusMonitor.Tests;

public sealed class AdminSpeedLogicTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 27, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TheListsAreFetchedWhenNeverLoadedOrOlderThanAMinute()
    {
        Assert.True(AdminFlow.ListsAreStale(null, Now));
        Assert.False(AdminFlow.ListsAreStale(Now.AddSeconds(-59), Now));
        Assert.True(AdminFlow.ListsAreStale(Now.AddSeconds(-60), Now));
    }

    [Theory]
    [InlineData(100, 100, null)]
    [InlineData(40, 40, null)]
    [InlineData(100, 922, "Show 100 more (822 not shown)")]
    [InlineData(900, 922, "Show 22 more (22 not shown)")]
    public void TheMoreButtonSaysHowManyAreHidden(int showing, int matching, string? label) =>
        Assert.Equal(label, AdminFlow.MoreAgentsLabel(showing, matching));
}

/// <summary>The Admin page on a bus with hundreds of agents.</summary>
[Collection(StaWindowAdminCollection.Name)]
public class AdminSpeedWindowTests(StaWindowAdminFixture sta)
{
    private const int Agents = 922;

    private static string AgentJson(int index) =>
        $$"""{"id":"a{{index}}","name":"worker-{{index:D4}}","description":"","host":"box-{{index % 7}}","state":"enabled","credential_epoch":1,"last_seen_at":null,"actions":[{"action":"block","effect":"Block."}]}""";

    /// <summary>Serves the agents 200 at a time, by the name after which the next page starts, as the bus does.</summary>
    private static StaWindowAdminScene Open(int agents = Agents)
    {
        var scene = new StaWindowAdminScene().Enroll();
        try
        {
            var all = Enumerable.Range(1, agents).Select(index => (Name: $"worker-{index:D4}", Json: AgentJson(index))).ToList();
            scene.Bus.On("GET /api/mobile/admin/agents", request =>
            {
                var after = Uri.UnescapeDataString(request.Query.Split('&').FirstOrDefault(part => part.StartsWith("after=", StringComparison.Ordinal))?[6..] ?? string.Empty);
                var page = all.Where(agent => string.CompareOrdinal(agent.Name, after) > 0).Take(200);
                return StaWindowAdminBus.Ok("[" + string.Join(",", page.Select(agent => agent.Json)) + "]");
            });
            scene.Bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok("[]"));
            scene.Bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok("[]"));
            scene.Open();
            scene.Window.AdminNav.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.AdminDevicesSummary.Text.Length > 0, "the Admin lists");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static int AgentRequests(StaWindowAdminScene scene) => scene.Bus.RequestsTo("GET /api/mobile/admin/agents").Count;

    [Fact]
    public void OnlyTheFirstHundredRowsAreBuiltAndTheRestAreAButtonAway() => sta.Run(() =>
    {
        using var scene = Open();
        var window = scene.Window;

        Assert.Equal(100, window.AdminAgentList.Items.Count);
        Assert.Equal(Visibility.Visible, window.AdminAgentsMore.Visibility);
        Assert.Equal("Show 100 more (822 not shown)", window.AdminAgentsMore.Content);
        // The summary still counts every agent, not only the rows on screen.
        Assert.Contains("922", window.AdminAgentsSummary.Text);

        StaWindowAdminScene.Click(window.AdminAgentsMore);

        Assert.Equal(200, window.AdminAgentList.Items.Count);
        Assert.Equal("Show 100 more (722 not shown)", window.AdminAgentsMore.Content);
    });

    [Fact]
    public void TheFilterSearchesEveryAgentNotOnlyTheRowsOnScreen() => sta.Run(() =>
    {
        using var scene = Open();
        var window = scene.Window;
        StaWindowAdminScene.Click(window.AdminAgentsMore);

        window.AdminAgentFilter.Text = "worker-0917";

        var row = Assert.IsType<AdminRow>(Assert.Single(window.AdminAgentList.Items));
        Assert.Equal("worker-0917", row.Name);
        Assert.Equal(Visibility.Collapsed, window.AdminAgentsMore.Visibility);
        Assert.Equal("1 of 922 agents match.", window.AdminAgentsSummary.Text);

        // Clearing the filter goes back to the first hundred, not to wherever "more" had got to.
        window.AdminAgentFilter.Text = string.Empty;

        Assert.Equal(100, window.AdminAgentList.Items.Count);
    });

    [Fact]
    public void AShortListHasNoMoreButton() => sta.Run(() =>
    {
        using var scene = Open(agents: 40);

        Assert.Equal(40, scene.Window.AdminAgentList.Items.Count);
        Assert.Equal(Visibility.Collapsed, scene.Window.AdminAgentsMore.Visibility);
    });

    [Fact]
    public void ComingBackToAdminWithinAMinuteDoesNotFetchTheListsAgain() => sta.Run(() =>
    {
        using var scene = Open();
        var window = scene.Window;
        var fetched = AgentRequests(scene);
        // 922 agents, 200 to a page.
        Assert.Equal(5, fetched);

        window.MonitorNav.IsChecked = true;
        window.AdminNav.IsChecked = true;
        StaWindowAdminFixture.Drain();

        Assert.Equal(fetched, AgentRequests(scene));
        Assert.Equal(100, window.AdminAgentList.Items.Count);
    });

    [Fact]
    public void ReloadAlwaysFetchesAndKeepsTheRowsAlreadyShown() => sta.Run(() =>
    {
        using var scene = Open();
        var window = scene.Window;
        StaWindowAdminScene.Click(window.AdminAgentsMore);
        var fetched = AgentRequests(scene);

        var reload = new System.Windows.Controls.Button();
        window.AdminReload_Click(reload, new RoutedEventArgs());
        StaWindowAdminScene.WaitFor(reload);

        Assert.Equal(fetched + 5, AgentRequests(scene));
        Assert.Equal(200, window.AdminAgentList.Items.Count);
    });
}
