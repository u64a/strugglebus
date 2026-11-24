namespace StruggleBusMonitor.Tests;

public class AdminLogicTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);

    // Shaped exactly like the StruggleBus 0.2.64 responses, including fields this app ignores.
    private const string AgentsJson = """
        [{"id":"a1","name":"prox-manager","description":"Looks after the host","host":"pve1","state":"enabled",
          "credential_epoch":3,"created_at":"2026-11-01T00:00:00Z","last_seen_at":"2026-11-17T08:59:00Z",
          "blocked_at":null,"retired_at":null,
          "actions":[{"action":"block","effect":"Block this agent."},{"action":"retire","effect":"Retire this agent permanently."}]},
         {"id":"a2","name":"old-runner","description":"","host":"","state":"retired","credential_epoch":9,
          "created_at":"2026-10-01T00:00:00Z","last_seen_at":null,"blocked_at":null,
          "retired_at":"2026-11-02T00:00:00Z","actions":[]}]
        """;

    private const string DevicesJson = """
        [{"id":"d1","label":"desk-pc","status":"enabled","created_at":"2026-11-01T00:00:00Z",
          "last_seen_at":"2026-11-17T08:58:00Z","revoked_at":null,"has_write_grant":true,"this_device":true,
          "actions":[{"action":"revoke-device","effect":"Permanently revoke this device."}]}]
        """;

    private const string PrincipalsJson = """
        [{"id":"s1","name":"nightly-audit","agent_name_prefix":"audit-worker","status":"blocked","version":4,
          "created_at":"2026-11-01T00:00:00Z","blocked_at":"2026-11-16T00:00:00Z","revoked_at":null,
          "actions":[{"action":"unblock","effect":"Unblock."},{"action":"revoke","effect":"Revoke."}]}]
        """;

    [Fact]
    public void ParsesManagedAgentsAndBuildsRows()
    {
        var agents = BusApi.ParseManagedAgents(AgentsJson);

        Assert.Equal(2, agents.Count);
        Assert.Equal(3, agents[0].CredentialEpoch);
        var row = AdminLogic.AgentRow(agents[0], Now);
        Assert.Equal(AdminRowKind.Agent, row.Kind);
        Assert.Equal(3, row.Version);
        Assert.Equal("ENABLED", row.StateLabel);
        Assert.Equal("Ok", row.Tone);
        Assert.Equal("pve1  ·  active 1m ago  ·  Looks after the host", row.Meta);
        Assert.Equal(["Block", "Retire"], row.Actions.Select(action => action.Label));
        Assert.All(row.Actions, action => Assert.True(action.IsDanger));
        Assert.Same(row, row.Actions[0].Row);

        var retired = AdminLogic.AgentRow(agents[1], Now);
        Assert.Equal("Off", retired.Tone);
        Assert.Equal("retired", retired.Meta);
        Assert.Empty(retired.Actions);
    }

    [Fact]
    public void ParsesDevicesAndServicePrincipals()
    {
        var device = AdminLogic.DeviceRow(BusApi.ParseManagedDevices(DevicesJson).Single(), Now);
        Assert.True(device.IsThisDevice);
        Assert.Equal("this PC", device.Note);
        Assert.Equal("active 2m ago  ·  operator access saved", device.Meta);
        Assert.Equal("revoke-device", device.Actions.Single().Action);

        var principal = AdminLogic.ServicePrincipalRow(BusApi.ParseManagedServicePrincipals(PrincipalsJson).Single());
        Assert.Equal(4, principal.Version);
        Assert.Equal("Warn", principal.Tone);
        Assert.Equal("creates worker agents named audit-worker-*", principal.Meta);
        Assert.Equal(["Unblock", "Revoke"], principal.Actions.Select(action => action.Label));
        Assert.False(principal.Actions[0].IsDanger);
    }

    [Fact]
    public void ParsesControlResultWithAndWithoutASecret()
    {
        var rotated = BusApi.ParseControlResult("""
            {"action":"rotate","target_id":"s1","target_label":"nightly-audit","applied":true,"state":"enabled",
             "detail":"Credential replaced.","secret":"sbs1_x","secret_kind":"service-principal-credential"}
            """);
        Assert.Equal("sbs1_x", rotated.Secret);
        Assert.Equal("nightly-audit", rotated.TargetLabel);

        var blocked = BusApi.ParseControlResult("""
            {"action":"block","target_id":"a1","target_label":"prox-manager","applied":true,"state":"blocked",
             "detail":"Agent is now blocked.","secret":null,"secret_kind":null}
            """);
        Assert.Null(blocked.Secret);
        Assert.Equal("blocked", blocked.State);
    }

    [Fact]
    public void FilterMatchesEveryWordAndPutsBlockedFirst()
    {
        var rows = new[]
        {
            AdminLogic.AgentRow(new ManagedAgent("1", "zeta-agent", "", "pve1", "enabled", 1, Now, []), Now),
            AdminLogic.AgentRow(new ManagedAgent("2", "beta-agent", "", "pve2", "blocked", 1, Now, []), Now),
            AdminLogic.AgentRow(new ManagedAgent("3", "alpha-agent", "", "pve1", "retired", 1, null, []), Now),
            AdminLogic.AgentRow(new ManagedAgent("4", "alpha-two", "", "pve1", "enabled", 1, Now, []), Now)
        };

        Assert.Equal(["beta-agent", "alpha-two", "zeta-agent", "alpha-agent"], AdminLogic.Filter(rows, " ").Select(row => row.Name));
        Assert.Equal(["zeta-agent"], AdminLogic.Filter(rows, "PVE1 zeta").Select(row => row.Name));
        Assert.Equal(["beta-agent"], AdminLogic.Filter(rows, "blocked").Select(row => row.Name));
        Assert.Equal("4 agents, 1 blocked, 1 no longer active.", AdminLogic.Summary(rows, "agent"));
        Assert.Equal("No devices.", AdminLogic.Summary([], "device"));
    }

    [Fact]
    public void LegacyRowsOfferOnlyContainment()
    {
        var agent = AdminLogic.LegacyAgentRow(new BusAgent("a1", "prox-manager", "", "pve1", "seen", Now), Now);
        Assert.True(agent.Legacy);
        Assert.Equal("block-agent", agent.Actions.Single().Action);
        Assert.Equal("Block", agent.Actions.Single().Label);

        var device = AdminLogic.LegacyDeviceRow(new Session("https://bus", "c", [], "d1", "desk-pc"));
        Assert.True(device.IsThisDevice);
        Assert.Equal("revoke-device", device.Actions.Single().Action);
    }

    [Fact]
    public void ManagedAgentPathsPageByName()
    {
        Assert.Equal("api/mobile/admin/agents?state=managed&limit=200", BusApi.BuildManagedAgentsPath(false, null));
        Assert.Equal("api/mobile/admin/agents?state=all&limit=200&after=prox-manager", BusApi.BuildManagedAgentsPath(true, "prox-manager"));
    }
}
