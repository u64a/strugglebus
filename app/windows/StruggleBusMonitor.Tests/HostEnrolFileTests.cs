using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace StruggleBusMonitor.Tests;

public class HostEnrolFileTests
{
    private const string Key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDYWpfCDNW5PEj1Fldb+74c/5bsCxTzhdLOvXf0/V6IOcP1H3Kr1nddwSjVUI/4ipZFpGUiDLfksXjCeYGo+KtrfYVIY1EbrnRYgOKa/499xm7zzIrysttoQS5jc++2/fKlKkl3S0Se3TJh4f5YlraysDBiAj0EaikYZPtXjJXNM9fGgjRua5cvDULVsVVeSyvkIpHVZUWLa/+kKh4conEX7C2rpn36HBEu34NESh3MWf3KtjNKhgqA00nS9vAEv+W/U6T/AhA6ZIs6gRbT2PM8C6aunpQLxLDY0MpH1fzzfuBje1RWqfeTVqoaPE8WNdZfYCaTzaKRvvr4jEOp4M1f";
    private const string Namespaces = "namespaces=\"strugglebus-fleet,strugglebus-host-command\"";

    /// <summary>The worker host project's vector, tests/data/vectors/sbhost-enrol.json, byte for byte.</summary>
    private static byte[] Vector() => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Vectors", "sbhost-enrol.json"));

    /// <summary>The values that vector was rendered from.</summary>
    private static HostEnrolData VectorData() => new(
        WrittenAt: new DateTimeOffset(2026, 11, 24, 14, 2, 59, TimeSpan.FromHours(10)),
        Device: "office-laptop",
        BusUrl: "https://bus.example.lan",
        CaDer: Convert.FromBase64String("MIIBtest"),
        HostPrefix: "host-office1",
        EnrolCode: "sbhe1_A1b2C3d4E5f6G7h8I9j0K-_zzzzzzzzzzzzzzzzzzzzY_x-W9v8u7t6s5r4q3p2onm",
        Engines: ["claude", "ghcp"],
        Dedicated: true,
        Signers: [$"owner {Namespaces} ssh-rsa {Key} vector-key", $"backup {Namespaces} ssh-rsa {Key} vector-key"],
        FleetSource: "bus",
        Remotes: ["https://github.com/acme/"]);

    [Fact]
    public void TheFileMatchesTheInstallersVectorByteForByte()
    {
        var vector = Vector();
        // If this fails the vector was changed on checkout: it must stay exactly as published.
        Assert.Equal("42D75E14B586793374ADDFA1E22F1627BB887FEA0EB88AF7F16FDB06D61E9782", Convert.ToHexString(SHA256.HashData(vector)));

        Assert.Null(HostEnrolFile.Problem(VectorData()));
        Assert.Equal(Encoding.ASCII.GetString(vector), Encoding.ASCII.GetString(HostEnrolFile.Render(VectorData())));
        Assert.Equal(vector, HostEnrolFile.Render(VectorData()));
    }

    [Fact]
    public void TheFileIsOneAsciiLineWithNoSpacesBetweenValuesAndOneLineFeed()
    {
        var bytes = HostEnrolFile.Render(VectorData() with { Dedicated = false, Engines = ["ghcp"] });
        var text = Encoding.ASCII.GetString(bytes);

        Assert.All(bytes, value => Assert.InRange(value, (byte)0x0A, (byte)0x7E));
        Assert.Equal(1, text.Count(character => character == '\n'));
        Assert.EndsWith("}\n", text);
        Assert.StartsWith("{\"v\":1,\"written_at\":\"2026-11-24T04:02Z\",\"device\":", text);
        Assert.Contains("\"engines\":[\"ghcp\"],\"dedicated\":false,", text);
        // The plus, slash and equals signs are written as they are; only the double quote is escaped.
        Assert.Contains("+74c/5bs", text);
        Assert.DoesNotContain("\\u", text);
        Assert.Contains("namespaces=\\\"strugglebus-fleet,strugglebus-host-command\\\"", text);
        Assert.True(bytes.Length < HostEnrolFile.MaxBytes);
    }

    [Fact]
    public void ARealSizedCertificateBecomesPemWithSixtyFourCharacterLines()
    {
        var der = Enumerable.Range(0, 700).Select(index => (byte)index).ToArray();

        var pem = Encoding.ASCII.GetString(Convert.FromBase64String(HostEnrolFile.CaPemBase64(der)));

        var lines = pem.Split('\n');
        Assert.Equal("-----BEGIN CERTIFICATE-----", lines[0]);
        Assert.Equal("-----END CERTIFICATE-----", lines[^2]);
        Assert.Equal("", lines[^1]);
        Assert.All(lines[1..^3], line => Assert.Equal(64, line.Length));
        Assert.InRange(lines[^3].Length, 1, 64);
        Assert.Equal(der, Convert.FromBase64String(string.Concat(lines[1..^2])));
        Assert.DoesNotContain('\r', pem);
    }

    public static TheoryData<string, Func<HostEnrolData, HostEnrolData>> BadValues() => new()
    {
        { "device label", data => data with { Device = "Office Laptop" } },
        { "bus address", data => data with { BusUrl = "http://bus.example.lan" } },
        { "bus address", data => data with { BusUrl = "https://bus.example.lan/path" } },
        { "bus address", data => data with { BusUrl = "https://bus.example.lan' ; rm" } },
        { "certificate root", data => data with { CaDer = [] } },
        { "host name", data => data with { HostPrefix = "host--office" } },
        { "host name", data => data with { HostPrefix = "h" } },
        { "host name", data => data with { HostPrefix = "host-" + new string('a', 27) } },
        { "host code", data => data with { EnrolCode = "sbe1_wrong-kind" } },
        { "host code", data => data with { EnrolCode = "" } },
        { "Copilot", data => data with { Engines = [] } },
        { "Copilot", data => data with { Engines = ["claude", "claude"] } },
        { "Copilot", data => data with { Engines = ["gpt"] } },
        { "Copilot", data => data with { Engines = ["claude", "ghcp", "claude"] } },
        { "signer line", data => data with { Signers = [data.Signers[0], "owner namespaces=\"strugglebus-release\" ssh-rsa AAAA key"] } },
        { "signer line", data => data with { Signers = [data.Signers[0], data.Signers[1] + "\nextra"] } },
        { "signer line", data => data with { Signers = [data.Signers[0], "owner ssh-rsa AAAA key"] } },
        { "two signers", data => data with { Signers = [data.Signers[0]] } },
        { "two signers", data => data with { Signers = [] } },
        { "fleet source", data => data with { FleetSource = "ftp" } },
        { "repository location", data => data with { Remotes = [] } },
        { "repository location", data => data with { Remotes = ["https://github.com/acme"] } },
        { "repository location", data => data with { Remotes = ["https://github.com/acme/", "git@github.com:acme/"] } }
    };

    [Theory]
    [MemberData(nameof(BadValues))]
    public void AValueTheInstallerWouldRefuseIsNamed(string mentions, Func<HostEnrolData, HostEnrolData> change) =>
        Assert.Contains(mentions, HostEnrolFile.Problem(change(VectorData())));

    [Fact]
    public void TheDigestIsSixteenHexOfTheFileInFours()
    {
        var vector = Vector();
        var hex = Convert.ToHexStringLower(SHA256.HashData(vector));

        Assert.Equal($"{hex[..4]} {hex[4..8]} {hex[8..12]} {hex[12..16]}", HostEnrolFile.Digest(vector));
        Assert.Equal("42d7 5e14 b586 7933", HostEnrolFile.Digest(vector));
        Assert.Equal("42D75E14B586793374ADDFA1E22F1627BB887FEA0EB88AF7F16FDB06D61E9782", HostEnrolFile.Sha256(vector));
    }

    [Fact]
    public void ASignerFingerprintIsWhatSshKeygenPrints()
    {
        var expected = "SHA256:" + Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(Key))).TrimEnd('=');

        var fingerprint = HostEnrolFile.SignerFingerprint(VectorData().Signers[0]);

        Assert.Equal(expected, fingerprint);
        Assert.Matches("^SHA256:[A-Za-z0-9+/]{43}$", fingerprint);
    }
}
