using System.IO;
using System.Text;
using System.Text.Json;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// Composing the next fleet document, against the vectors shared with the worker host
/// (contracts/fleet/compose): the exact bytes for one added host, and each refusal.
/// </summary>
public sealed class FleetComposeVectorTests
{
    private static readonly string Folder = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");

    private static string Read(string name) => new UTF8Encoding(false, true).GetString(File.ReadAllBytes(Path.Combine(Folder, name)));

    private static JsonElement Expected() => JsonDocument.Parse(Read("expected.json")).RootElement;

    public static TheoryData<string> Cases() => new(Expected().GetProperty("cases").EnumerateArray().Select(entry => entry.GetProperty("name").GetString()!));

    private static string Vector(FleetRefusal refusal) => refusal switch
    {
        FleetRefusal.SerialLine => "refuse:serial-line",
        FleetRefusal.UnknownKey => "refuse:unknown-key",
        FleetRefusal.DuplicateAgent => "refuse:duplicate-agent",
        FleetRefusal.HostListed => "refuse:host-listed",
        FleetRefusal.SerialMismatch => "refuse:serial-mismatch",
        _ => "refuse:serial-ahead"
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void EachSharedCaseGivesItsExactBytesOrItsRefusal(string name)
    {
        var entry = Expected().GetProperty("cases").EnumerateArray().Single(candidate => candidate.GetProperty("name").GetString() == name);
        var add = entry.GetProperty("add");
        var result = entry.GetProperty("result").GetString()!;
        string Compose() => FleetCompose.Next(
            Read(entry.GetProperty("current").GetString()!), add.GetProperty("agent_name").GetString()!, add.GetProperty("agent_id").GetString()!,
            entry.GetProperty("bus_serial").GetInt64(), entry.GetProperty("reported").EnumerateArray().Select(value => value.GetInt64()));

        if (result.StartsWith("refuse:", StringComparison.Ordinal))
        {
            Assert.Equal(result, Vector(Assert.Throws<FleetRefusedException>(Compose).Reason));
        }
        else
        {
            Assert.Equal(Read(result), Compose());
        }
    }

    [Fact]
    public void TheSharedFlagVectorsReadAsTheySay()
    {
        foreach (var flag in Expected().GetProperty("flags").EnumerateObject().Where(entry => !entry.Name.StartsWith('_')))
        {
            var expected = flag.Value.ValueKind == JsonValueKind.Null ? (byte?)null : flag.Value.GetByte();
            Assert.Equal(expected, SshSignature.Read(Read(flag.Name))!.Flags);
        }
    }
}

/// <summary>The strict reading of a fleet document, beyond the shared cases.</summary>
public sealed class FleetComposeTests
{
    private const string NewName = "host-office2-host";
    private const string NewId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    private const string Fleet = """
        serial = 4

        # Whose decision merging is ("run by <coordinator> for <owner>").
        owner = "Alex"   # a comment after a value

        [[coordinator]]   # the first
        agent_name     = "coord-main"
        agent_id       = "11111111-1111-4111-8111-111111111111"
        project        = "app"
        notes_repo     = "https://github.com/acme/team-notes"
        notes_channel  = "app-notes"
        repos          = ["https://github.com/acme/", "https://github.com/other/"]
        default_engine = "claude"
        repo_instructions = true
        worker_rules   = \"\"\"
        Describe "attack paths" as findings. A line that starts with [ is still text.
        [not a table]
        \"\"\"

        [[host]]
        agent_name = "host-office1-host"
        agent_id   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

        """;

    private static string Text(string raw = Fleet) => raw.Replace("\\\"", "\"").Replace("\r\n", "\n");

    private static FleetRefusal Refusal(string text, long busSerial = 4, params long[] reported) =>
        Assert.Throws<FleetRefusedException>(() => FleetCompose.Next(text, NewName, NewId, busSerial, reported)).Reason;

    [Fact]
    public void ADocumentUsingEverythingAFleetUsesIsReadAndOnlyTheSerialAndTheEndChange()
    {
        var current = Text();

        var next = FleetCompose.Next(current, NewName, NewId, 4, [4, 3]);

        Assert.Equal(current.Replace("serial = 4\n", "serial = 5\n") + FleetCompose.HostBlock(NewName, NewId), next);
        Assert.Equal(
            [("coordinator", "coord-main"), ("host", "host-office1-host")],
            FleetCompose.Agents(current).Select(agent => (agent.Kind, agent.Name!)));
        Assert.Equal(3, FleetCompose.Agents(next).Count);
        Assert.Equal(5, FleetCompose.SerialOf(next));
    }

    [Theory]
    [InlineData("owner = 'Alex'")]
    [InlineData("owner = \"Al\\\\ex\"")]
    [InlineData("owner = \"Alex\" trailing")]
    [InlineData("owner.name = \"Alex\"")]
    [InlineData("Owner = \"Alex\"")]
    [InlineData("colour = \"blue\"")]
    [InlineData("owner = \"Alex\"\nowner = \"Sam\"")]
    [InlineData("just words")]
    [InlineData("[host]")]
    [InlineData("[[hosts]]")]
    [InlineData("[[host]]\nagent_name = \"host-x-host\"\nnotes = \"extra\"")]
    [InlineData("[[coordinator]]\nrepos = [\"https://a/\",\n\"https://b/\"]")]
    [InlineData("[[coordinator]]\nworker_rules = \"\"\"\nnever closed")]
    [InlineData("[[coordinator]]\nworker_rules = \"\"\"\ntext\n\"\"\" and more")]
    public void AnythingOutsideTheFleetSchemaIsRefusedNotGuessedAt(string addition)
    {
        Assert.Equal(FleetRefusal.UnknownKey, Refusal("serial = 4\n" + addition + "\n"));
    }

    [Theory]
    [InlineData("owner = \"Alex\"\n")]
    [InlineData("serial=4\n")]
    [InlineData("serial = 4\n[[host]]\nserial = 4\n")]
    [InlineData("serial = 4 # four\n")]
    [InlineData("serial = 4")]
    public void TheSerialMustBeTheOneLineTheAppWouldWrite(string text) => Assert.Equal(FleetRefusal.SerialLine, Refusal(text));

    [Fact]
    public void AMultiLineTextMayCloseOnItsOpeningLineOrWithACommentAfter()
    {
        var text = "serial = 4\n[[coordinator]]\nworker_rules = \"\"\"one line\"\"\"\nproject = \"app\"\n[[coordinator]]\nworker_rules = \"\"\"\ntwo\n\"\"\"  # done\n";

        Assert.Equal(2, FleetCompose.Agents(text).Count);
    }

    [Fact]
    public void TwoTablesWithNoNameCountAsTheSameAgent() =>
        Assert.Equal(FleetRefusal.DuplicateAgent, Refusal("serial = 4\n[[host]]\nagent_id = \"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"\n[[host]]\nagent_id = \"cccccccc-cccc-4ccc-8ccc-cccccccccccc\"\n"));

    [Fact]
    public void TheSerialsMustAgreeAndNoHostMayBeAhead()
    {
        Assert.Equal(FleetRefusal.SerialMismatch, Refusal(Text(), busSerial: 5));
        Assert.Equal(FleetRefusal.SerialAhead, Refusal(Text(), 4, 4, 7));

        var error = Assert.Throws<FleetRefusedException>(() => FleetCompose.Next(Text(), NewName, NewId, 4, [9, 7]));
        Assert.Contains("reports fleet serial 9, which is above the bus's serial 4", error.Message);
    }

    [Theory]
    [InlineData("host-office2", NewId, "is not a worker host's agent name")]
    [InlineData("Host-Office2-host", NewId, "is not a worker host's agent name")]
    [InlineData("host-office2-host\"\n[[coordinator]]", NewId, "is not a worker host's agent name")]
    [InlineData(NewName, "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB", "not a lower-case UUID")]
    [InlineData(NewName, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\"", "not a lower-case UUID")]
    public void OnlyARealHostNameAndIdAreEverWrittenIntoTheDocument(string name, string id, string expected)
    {
        Assert.Contains(expected, FleetCompose.HostProblem(name, id));
        Assert.Contains(expected, Assert.Throws<InvalidOperationException>(() => FleetCompose.Next(Text(), name, id, 4, [])).Message);
        Assert.Null(FleetCompose.HostProblem(NewName, NewId));
    }
}
