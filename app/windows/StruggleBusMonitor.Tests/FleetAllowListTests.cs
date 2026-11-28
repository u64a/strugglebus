using System.IO;
using System.Text;
using System.Text.Json;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// Authorising and removing coordinators, and removing hosts, against the vectors shared with the
/// worker host (contracts/fleet/compose/coordinators.json and not-a-fleet.json).
/// </summary>
public sealed class FleetAllowListVectorTests
{
    private static readonly string Folder = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");

    private static string Read(string name) => new UTF8Encoding(false, true).GetString(File.ReadAllBytes(Path.Combine(Folder, name)));

    private static JsonElement Coordinators() => JsonDocument.Parse(Read("coordinators.json")).RootElement;

    private static JsonElement NotAFleet() => JsonDocument.Parse(Read("not-a-fleet.json")).RootElement;

    public static TheoryData<string> Cases() => new(Coordinators().GetProperty("cases").EnumerateArray().Select(entry => entry.GetProperty("name").GetString()!));

    private static readonly Dictionary<FleetRefusal, string> Names = new()
    {
        [FleetRefusal.SerialLine] = "serial-line", [FleetRefusal.UnknownKey] = "unknown-key", [FleetRefusal.DuplicateAgent] = "duplicate-agent",
        [FleetRefusal.HostListed] = "host-listed", [FleetRefusal.SerialMismatch] = "serial-mismatch", [FleetRefusal.SerialAhead] = "serial-ahead",
        [FleetRefusal.UnsafeChar] = "unsafe-char", [FleetRefusal.BadValue] = "bad-value", [FleetRefusal.OutsideRemotes] = "outside-remotes",
        [FleetRefusal.NotListed] = "not-listed", [FleetRefusal.LastCoordinator] = "last-coordinator", [FleetRefusal.HandEdited] = "hand-edited",
        [FleetRefusal.FleetExists] = "fleet-exists"
    };

    private static string Vector(FleetRefusedException refusal) =>
        "refuse:" + Names[refusal.Reason] + (refusal.Field is null ? string.Empty : ":" + refusal.Field);

    private static List<string> Texts(JsonElement list) => list.EnumerateArray().Select(value => value.GetString()!).ToList();

    private static CoordinatorEntry Entry(JsonElement entry) => new(
        entry.GetProperty("agent_name").GetString()!, entry.GetProperty("agent_id").GetString()!, entry.GetProperty("project").GetString()!,
        entry.GetProperty("notes_repo").GetString()!, entry.GetProperty("notes_channel").GetString()!, Texts(entry.GetProperty("repos")),
        entry.TryGetProperty("default_engine", out var engine) ? engine.GetString() : null);  // optional (PR 97)

    [Theory]
    [MemberData(nameof(Cases))]
    public void EachSharedCaseGivesItsExactBytesOrItsRefusal(string name)
    {
        var root = Coordinators();
        var entry = root.GetProperty("cases").EnumerateArray().Single(candidate => candidate.GetProperty("name").GetString() == name);
        var current = Read(entry.GetProperty("current").GetString()!);
        var busSerial = entry.GetProperty("bus_serial").GetInt64();
        var reported = entry.GetProperty("reported").EnumerateArray().Select(value => value.GetInt64()).ToList();
        var operation = entry.GetProperty("op").GetString()!;
        var result = entry.GetProperty("result").GetString()!;
        IReadOnlyList<string> warnings = [];

        string Compose()
        {
            if (operation != "add-coordinator") return FleetAllowList.Remove(current, operation["remove-".Length..], entry.GetProperty("agent_name").GetString()!, busSerial, reported);
            var (text, broad) = FleetAllowList.Add(current, Entry(entry.GetProperty("entry")), busSerial, reported, Texts(root.GetProperty("remotes")));
            warnings = broad.Select(prefix => "broad-prefix:" + prefix).ToList();
            return text;
        }

        if (result.StartsWith("refuse:", StringComparison.Ordinal))
        {
            Assert.Equal(result, Vector(Assert.Throws<FleetRefusedException>(Compose)));
            return;
        }

        Assert.Equal(Read(result), Compose());
        if (entry.TryGetProperty("warnings", out var expected)) Assert.Equal(Texts(expected), warnings);
    }

    [Fact]
    public void TheSharedListOfNamespacesNeverToSignIsRefusedAtTheLowestLayer()
    {
        var root = NotAFleet();
        Assert.Equal(FleetSignLogic.Namespace, root.GetProperty("sign_namespace").GetString());
        var never = Texts(root.GetProperty("never_sign_namespaces"));
        Assert.NotEmpty(never);
        Assert.All(never, purpose => Assert.Throws<InvalidOperationException>(() => SshKeygen.RequireSignablePurpose(purpose)));
    }

    [Fact]
    public void TheSharedReleaseAndStatementInputsAreNeverReadAsAFleet()
    {
        var cases = NotAFleet().GetProperty("cases").EnumerateArray().ToList();
        Assert.NotEmpty(cases);
        foreach (var entry in cases)
        {
            var input = File.ReadAllBytes(Path.Combine(Folder, entry.GetProperty("input").GetString()!));

            var refusal = Assert.Throws<FleetRefusedException>(() => FleetSignLogic.RequireFleet(input));

            Assert.Equal(entry.GetProperty("result").GetString(), Vector(refusal));
        }
    }
}

/// <summary>The address rules and the wording, beyond the shared cases.</summary>
public sealed class FleetAllowListTests
{
    [Theory]
    [InlineData("https://github.com/acme/repo", true)]
    [InlineData("https://github.com/acme/repo.git", true)]
    [InlineData("https://github.com/acme/", false)]
    [InlineData("https://github.com/acme/repo/extra", false)]
    [InlineData("http://github.com/acme/repo", false)]
    [InlineData("https://GitHub.com/acme/repo", false)]
    [InlineData("https://user@github.com/acme/repo", false)]
    [InlineData("https://github.com:443/acme/repo", false)]
    [InlineData("https://github.com/acme/repo?x=1", false)]
    [InlineData("https://github.com/acme/repo#x", false)]
    [InlineData("https://github.com/acme/..", false)]
    [InlineData("https://github.com/acme/.git", false)]
    [InlineData("https://github.com/ac me/repo", false)]
    [InlineData("https://github.com/acme/re\tpo", false)]
    [InlineData("https://github.com", false)]
    public void ARepositoryAddressIsExactlyHostOwnerAndRepository(string url, bool good) =>
        Assert.Equal(good, FleetAllowList.Repository(url) is not null);

    [Theory]
    [InlineData("https://github.com/", true)]
    [InlineData("https://github.com/acme/", true)]
    [InlineData("https://github.com/acme/repo", true)]
    [InlineData("https://github.com/acme/repo/", false)]
    [InlineData("https://github.com/acme", false)]
    [InlineData("https://github.com/../", false)]
    public void ALocationIsAHostAnOwnerOrOneRepository(string prefix, bool good) => Assert.Equal(good, FleetAllowList.PrefixOk(prefix));

    [Theory]
    [InlineData("https://github.com/acme/repo", "https://github.com/acme/", true)]
    [InlineData("https://github.com/acme-evil/repo", "https://github.com/acme/", false)]
    [InlineData("https://github.com/acme/repo", "https://github.com/", true)]
    [InlineData("https://github.com/acme/repo.git", "https://github.com/acme/repo", true)]
    [InlineData("https://github.com/acme/other", "https://github.com/acme/repo", false)]
    [InlineData("https://gitlab.com/acme/repo", "https://github.com/acme/", false)]
    [InlineData("https://github.com/acme/", "https://github.com/acme/", true)]
    [InlineData("https://github.com/", "https://github.com/acme/", false)]
    [InlineData("https://github.com/acme/", "https://github.com/", true)]
    [InlineData("https://github.com/acme/", "https://gitlab.com/", false)]
    [InlineData("https://github.com/acme/", "not a url", false)]
    public void ALocationIsInsideAnAllowedOneByWholePathSegmentsAndNeverWider(string url, string remote, bool inside) =>
        Assert.Equal(inside, FleetAllowList.Within(url, remote));

    private static readonly CoordinatorEntry Good = new(
        "coord-docs", "22222222-2222-4222-8222-222222222222", "docs", "https://github.com/acme/docs-notes", "docs-notes", ["https://github.com/acme/handbook"], "claude");

    private static readonly string[] Remotes = ["https://github.com/acme/"];

    private static FleetRefusedException Refusal(CoordinatorEntry entry) => Assert.Throws<FleetRefusedException>(() => FleetAllowList.CheckEntry(entry, Remotes));

    [Fact]
    public void EachValueIsHeldToTheHostsOwnPatternInTheOrderItIsWritten()
    {
        FleetAllowList.CheckEntry(Good, Remotes);
        Assert.Equal("agent_name", Refusal(Good with { AgentName = "Coord", AgentId = "x" }).Field);
        Assert.Equal("agent_id", Refusal(Good with { AgentId = "22222222-2222-4222-8222-22222222222G" }).Field);
        Assert.Equal("project", Refusal(Good with { Project = "Docs" }).Field);
        Assert.Equal("notes_repo", Refusal(Good with { NotesRepo = "https://github.com/acme/" }).Field);
        Assert.Equal("notes_channel", Refusal(Good with { NotesChannel = "docs notes" }).Field);
        Assert.Equal("repos", Refusal(Good with { Repos = [] }).Field);
        Assert.Equal("default_engine", Refusal(Good with { DefaultEngine = "gpt" }).Field);
        Assert.All(
            new[] { "agent_name", "agent_id", "project", "notes_repo", "notes_channel", "repos", "default_engine" },
            field => Assert.NotEqual(string.Empty, Refusal(field switch
            {
                "agent_name" => Good with { AgentName = "" },
                "agent_id" => Good with { AgentId = "" },
                "project" => Good with { Project = "" },
                "notes_repo" => Good with { NotesRepo = "" },
                "notes_channel" => Good with { NotesChannel = "" },
                "repos" => Good with { Repos = ["nope"] },
                _ => Good with { DefaultEngine = "" }
            }).Message));
    }

    [Theory]
    [InlineData("https://github.com/acme/x\"")]
    [InlineData("https://github.com/acme/x\\")]
    [InlineData("https://github.com/acme/x\n[[coordinator]]")]
    [InlineData("https://github.com/acme/x#")]
    [InlineData("https://github.com/acme/[x]")]
    public void NoCharacterThatCouldBreakOutOfATextEverReachesTheDocument(string hostile)
    {
        Assert.Equal((FleetRefusal.UnsafeChar, "notes_repo"), (Refusal(Good with { NotesRepo = hostile }).Reason, Refusal(Good with { NotesRepo = hostile }).Field));
        Assert.Equal((FleetRefusal.UnsafeChar, "repos"), (Refusal(Good with { Repos = [hostile] }).Reason, Refusal(Good with { Repos = [hostile] }).Field));
    }

    [Fact]
    public void AnEntryWithNoEngineIsValidAndWritesNoEngineLine()
    {
        var entry = Good with { DefaultEngine = null };

        FleetAllowList.CheckEntry(entry, Remotes);
        Assert.DoesNotContain("default_engine", FleetAllowList.Block(entry));
        Assert.EndsWith("repos          = [\"https://github.com/acme/handbook\"]\n", FleetAllowList.Block(entry));
    }

    [Fact]
    public void TheTableIsWrittenWithEveryKeyPaddedAlike()
    {
        var block = FleetAllowList.Block(Good with { Repos = ["https://github.com/acme/", "https://github.com/acme/handbook"] });

        Assert.Equal(
            "\n[[coordinator]]\n" +
            "agent_name     = \"coord-docs\"\n" +
            "agent_id       = \"22222222-2222-4222-8222-222222222222\"\n" +
            "project        = \"docs\"\n" +
            "notes_repo     = \"https://github.com/acme/docs-notes\"\n" +
            "notes_channel  = \"docs-notes\"\n" +
            "repos          = [\"https://github.com/acme/\", \"https://github.com/acme/handbook\"]\n" +
            "default_engine = \"claude\"\n",
            block);
    }
}
