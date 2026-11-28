using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;

namespace StruggleBusMonitor.Tests;

/// <summary>Builds OpenSSH signature files for tests. Nothing here signs: the signature bytes are filler.</summary>
internal static class SshSignatureMaker
{
    public const string HardwareKey = "sk-ssh-ed25519@openssh.com";

    private static byte[] Field(byte[] value)
    {
        var field = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt32BigEndian(field, (uint)value.Length);
        value.CopyTo(field, 4);
        return field;
    }

    private static byte[] Field(string value) => Field(Encoding.ASCII.GetBytes(value));

    private static byte[] Join(params byte[][] parts) => parts.SelectMany(part => part).ToArray();

    /// <summary>A public key blob of the given type. <paramref name="seed"/> makes two keys differ.</summary>
    public static byte[] Key(string type = HardwareKey, byte seed = 1) =>
        Join(Field(type), Field(Enumerable.Repeat(seed, 32).ToArray()), Field("ssh:"));

    public static string SignerLine(byte[] key, string type = HardwareKey, string principal = "chris", string namespaces = "strugglebus-fleet,strugglebus-host-command") =>
        $"{principal} namespaces=\"{namespaces}\" {type} {Convert.ToBase64String(key)}";

    /// <summary>A signature file claiming the given key, purpose and, for a hardware key, flags.</summary>
    public static string File(byte[] key, string purpose = FleetPublishLogic.Namespace, byte? flags = 0x05, string type = HardwareKey, string? signedAs = null, byte[]? trailing = null)
    {
        var signature = Join(Field(signedAs ?? type), Field(new byte[64]));
        if (flags is { } value) signature = Join(signature, [value], [0, 0, 0, 7]);
        var blob = Join("SSHSIG"u8.ToArray(), [0, 0, 0, 1], Field(key), Field(purpose), Field(""), Field("sha512"), Field(signature), trailing ?? []);
        return Armour(blob);
    }

    public static string Armour(byte[] blob)
    {
        var text = Convert.ToBase64String(blob);
        var lines = Enumerable.Range(0, (text.Length + 69) / 70).Select(index => text.Substring(index * 70, Math.Min(70, text.Length - index * 70)));
        return SshSignature.Begin + "\n" + string.Join("\n", lines) + "\n" + SshSignature.End + "\n";
    }
}

/// <summary>What a signature file says about itself.</summary>
public sealed class SshSignatureTests
{
    private static readonly byte[] Key = SshSignatureMaker.Key();

    [Fact]
    public void AHardwareKeySignatureGivesItsKeyPurposeAndFlags()
    {
        var signature = SshSignature.Read(SshSignatureMaker.File(Key));

        Assert.Equal(
            (SshSignatureMaker.HardwareKey, Convert.ToBase64String(Key), "strugglebus-fleet", "sha512", (byte?)0x05),
            (signature!.KeyType, signature.KeyBase64, signature.Namespace, signature.HashAlgorithm, signature.Flags));
        Assert.Equal((byte?)0x01, SshSignature.Read(SshSignatureMaker.File(Key, flags: 0x01))!.Flags);
    }

    [Fact]
    public void WindowsLineEndingsAreReadTheSame() =>
        Assert.NotNull(SshSignature.Read(SshSignatureMaker.File(Key).Replace("\n", "\r\n")));

    [Fact]
    public void ARealSignatureFromTheSharedVectorsIsRead()
    {
        var folder = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet");
        var signature = SshSignature.Read(File.ReadAllText(Path.Combine(folder, "fleet.toml.sig")));
        var signer = File.ReadAllText(Path.Combine(folder, "allowed_signers")).Trim().Split(' ');

        Assert.Equal(("ssh-rsa", signer[3], "strugglebus-fleet", (byte?)null), (signature!.KeyType, signature.KeyBase64, signature.Namespace, signature.Flags));
    }

    public static TheoryData<string?> NotSignatures()
    {
        var good = SshSignatureMaker.File(Key);
        return new TheoryData<string?>
        {
            null,
            "",
            "not a signature",
            good.Replace("BEGIN SSH", "BEGIN PGP"),
            good.Replace(SshSignature.End, ""),
            SshSignature.Begin + "\n!!!!\n" + SshSignature.End + "\n",
            SshSignature.Begin + "\n" + SshSignature.End + "\n",
            SshSignatureMaker.Armour("SSHSIX"u8.ToArray()),
            SshSignatureMaker.Armour([.. "SSHSIG"u8, 0, 0, 0, 2]),
            SshSignatureMaker.Armour([.. "SSHSIG"u8, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF]),
            SshSignatureMaker.Armour([.. "SSHSIG"u8, 0, 0, 0, 1, 0, 0, 0, 9, 1]),
            SshSignatureMaker.File(Key, trailing: [0]),
            SshSignatureMaker.File(Key, flags: null),
            SshSignatureMaker.File(Key, signedAs: "ssh-ed25519"),
            SshSignatureMaker.File(SshSignatureMaker.Key("ssh-ed25519"), type: "ssh-ed25519", flags: 0x05),
            SshSignatureMaker.File(Key, purpose: "has space"),
            new string('A', SshSignature.MaxLength + 1)
        };
    }

    [Theory]
    [MemberData(nameof(NotSignatures))]
    public void AnythingMalformedIsNotASignature(string? text) => Assert.Null(SshSignature.Read(text));
}

/// <summary>The rules for publishing a fleet document signed elsewhere.</summary>
public sealed class FleetPublishLogicTests
{
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly byte[] OtherKey = SshSignatureMaker.Key(seed: 2);
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("serial = 4\nowner = \"Alex\"\n\n[[host]]\nagent_name = \"host-a-host\"\n");
    private static readonly IReadOnlyList<SiteSigner> Held = FleetPublishLogic.Signers(SshSignatureMaker.SignerLine(Key) + "\r\nnot a signer line\n");

    private static string Refusal(Action act) => Assert.Throws<InvalidOperationException>(act).Message;

    [Fact]
    public void TheSignerLinesHeldOnThisPcAreReadAndAnythingElseIsLeftOut()
    {
        var signer = Assert.Single(Held);

        Assert.Equal(("chris", SshSignatureMaker.HardwareKey, Convert.ToBase64String(Key)), (signer.Principal, signer.KeyType, signer.KeyBase64));
        Assert.Equal(["strugglebus-fleet", "strugglebus-host-command"], signer.Namespaces);
        Assert.Equal(HostEnrolFile.SignerFingerprint(signer.Line), signer.Fingerprint);
        Assert.Empty(FleetPublishLogic.Signers(""));
    }

    [Fact]
    public void AGoodDocumentAndSignatureGiveTheSerialAndTheSigner()
    {
        var fleet = FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key).Replace("\n", "\r\n"), Held);

        Assert.Equal((4L, "chris"), (fleet.Serial, fleet.Signer.Principal));
        Assert.DoesNotContain('\r', fleet.Signature);
        Assert.Same(Body, fleet.Body);
    }

    [Fact]
    public void EachThingWrongWithTheSignatureIsRefusedInWords()
    {
        Assert.Equal(FleetPublishLogic.NoSigners, Refusal(() => FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key), [])));
        Assert.Equal(FleetPublishLogic.NotASignature, Refusal(() => FleetPublishLogic.Check(Body, "junk", Held)));
        Assert.Equal(FleetPublishLogic.WrongPurpose, Refusal(() => FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key, purpose: "strugglebus-host-command"), Held)));
        Assert.Equal(FleetPublishLogic.UnknownSigner, Refusal(() => FleetPublishLogic.Check(Body, SshSignatureMaker.File(OtherKey), Held)));
        Assert.Equal(FleetPublishLogic.NoTouchAndPin, Refusal(() => FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key, flags: 0x01), Held)));
        Assert.Equal(FleetPublishLogic.NoTouchAndPin, Refusal(() => FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key, flags: 0x07), Held)));
    }

    [Fact]
    public void AHeldKeyThatIsNotForFleetsOrNotAHardwareKeyIsRefused()
    {
        var commandsOnly = FleetPublishLogic.Signers(SshSignatureMaker.SignerLine(Key, namespaces: "strugglebus-host-command"));
        Assert.Equal(FleetPublishLogic.UnknownSigner, Refusal(() => FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key), commandsOnly)));

        var plainKey = SshSignatureMaker.Key("ssh-ed25519");
        var plain = FleetPublishLogic.Signers(SshSignatureMaker.SignerLine(plainKey, "ssh-ed25519"));
        var signature = SshSignatureMaker.File(plainKey, type: "ssh-ed25519", flags: null);
        Assert.Equal(FleetPublishLogic.NotAHardwareKey, Refusal(() => FleetPublishLogic.Check(Body, signature, plain)));
    }

    [Theory]
    [InlineData("", "The document is empty.")]
    [InlineData("﻿serial = 4\n", "byte-order mark")]
    [InlineData("serial = 4\r\n", "Windows line endings")]
    public void ADocumentHostsWouldRefuseIsRefusedHere(string text, string expected)
    {
        var body = new UTF8Encoding(false).GetBytes(text);

        Assert.Contains(expected, FleetPublishLogic.BodyProblem(body));
        Assert.EndsWith("It is not published.", Refusal(() => FleetPublishLogic.Check(body, SshSignatureMaker.File(Key), Held)));
    }

    [Fact]
    public void ADocumentThatIsTooLongOrNotTextIsRefused()
    {
        Assert.Contains("at most 65,536", FleetPublishLogic.BodyProblem(new byte[FleetPublishLogic.MaxBytes + 1]));
        Assert.Null(FleetPublishLogic.BodyProblem(Encoding.UTF8.GetBytes(new string('a', FleetPublishLogic.MaxBytes))));
        Assert.Equal("The document is not valid UTF-8.", FleetPublishLogic.BodyProblem([0x73, 0xFF, 0x0A]));
    }

    [Theory]
    [InlineData("serial = 4\n", 4L)]
    [InlineData("# fleet\nowner = \"A\"\nserial=12   # twelve\n[[host]]\nserial = 99\n", 12L)]
    [InlineData("serial\t=\t7\n", 7L)]
    [InlineData("owner = \"A\"\n", null)]
    [InlineData("serial = 4\nserial = 5\n", null)]
    [InlineData("serial = 04\n", null)]
    [InlineData("serial = 0\n", null)]
    [InlineData("serial = -4\n", null)]
    [InlineData(" serial = 4\n", null)]
    [InlineData("[[host]]\nserial = 4\n", null)]
    [InlineData("serial = 4 5\n", null)]
    public void TheSerialIsTheOneSerialLineBeforeTheFirstTable(string text, long? expected)
    {
        Assert.Equal(expected, FleetPublishLogic.Serial(Encoding.UTF8.GetBytes(text)));
        if (expected is null) Assert.Equal(FleetPublishLogic.NoSerial, Refusal(() => FleetPublishLogic.Check(Encoding.UTF8.GetBytes(text), SshSignatureMaker.File(Key), Held)));
    }

    [Fact]
    public void OnlyAVerifiedSignatureGoesOn()
    {
        Assert.Null(FleetPublishLogic.VerdictProblem(SshVerdict.Good));
        Assert.Equal(FleetPublishLogic.BadSignature, FleetPublishLogic.VerdictProblem(SshVerdict.Bad));
        Assert.Equal(FleetPublishLogic.NoTool, FleetPublishLogic.VerdictProblem(SshVerdict.NoTool));
    }

    [Fact]
    public void ASerialThatDoesNotRiseAboveTheBussIsRefusedBeforeAnythingIsAsked()
    {
        Assert.Null(FleetPublishLogic.SerialProblem(4, null));
        Assert.Null(FleetPublishLogic.SerialProblem(5, 4));
        Assert.Contains("already holds fleet serial 4", FleetPublishLogic.SerialProblem(4, 4));
        Assert.Contains("already holds fleet serial 9", FleetPublishLogic.SerialProblem(4, 9));
    }

    [Fact]
    public void TheQuestionSaysWhatIsPublishedWhoSignedItAndWhatItReplaces()
    {
        var fleet = FleetPublishLogic.Check(Body, SshSignatureMaker.File(Key), Held);

        var first = FleetPublishLogic.ConfirmText(fleet, null);
        Assert.StartsWith("Publish fleet serial 4 to the bus?", first);
        Assert.Contains($"Signed by chris, {fleet.Signer.Fingerprint}.", first);
        Assert.Contains("The bus holds no fleet document yet.", first);
        Assert.Contains("It replaces serial 3.", FleetPublishLogic.ConfirmText(fleet, 3));
        Assert.Equal("Publish fleet serial 4 to the bus", FleetPublishLogic.HelloPrompt(4));
        Assert.StartsWith("Published fleet serial 4 at ", FleetPublishLogic.ResultText(fleet, DateTimeOffset.UnixEpoch));
    }
}

/// <summary>Windows' own ssh-keygen against the shared fleet vectors. These really verify.</summary>
public sealed class SshKeygenTests
{
    private static readonly string Folder = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet");

    private static Task<SshVerdict> VerifyAsync(string document, string? tool = null)
    {
        var signer = File.ReadAllText(Path.Combine(Folder, "allowed_signers")).Trim();
        return SshKeygen.VerifyAsync(
            tool ?? SshKeygen.DefaultPath, File.ReadAllBytes(Path.Combine(Folder, document)), File.ReadAllText(Path.Combine(Folder, document + ".sig")),
            signer, signer.Split(' ')[0], FleetPublishLogic.Namespace);
    }

    [Fact]
    public async Task TheGoodVectorVerifiesAndTheBadOnesDoNot()
    {
        Assert.Equal(SshVerdict.Good, await VerifyAsync("fleet.toml"));
        Assert.Equal(SshVerdict.Bad, await VerifyAsync("fleet-changed-byte.toml"));
        Assert.Equal(SshVerdict.Bad, await VerifyAsync("fleet-wrong-namespace.toml"));
    }

    [Fact]
    public async Task AMissingToolIsSaidNotGuessed() =>
        Assert.Equal(SshVerdict.NoTool, await VerifyAsync("fleet.toml", Path.Combine(Folder, "no-such-ssh-keygen.exe")));

    [Fact]
    public void TheToolIsWindowsOwnByFullPath() =>
        Assert.Equal(Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe"), SshKeygen.DefaultPath);
}

/// <summary>Publishing a signed fleet document from the real window.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class FleetPublishWindowTests(StaWindowAdminFixture sta)
{
    private const string Read = "GET /api/mobile/site-documents/fleet";
    private const string Publish = "POST /api/mobile/site-documents/fleet";
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("serial = 4\n\n[[host]]\nagent_name = \"host-a-host\"\n");

    private static string Stored(long serial) => JsonSerializer.Serialize(new
    {
        name = "fleet", serial, body = Convert.ToBase64String(Body), signature = "sig", signer_fingerprint = "SHA256:x", stored_at = "2030-01-02T03:04:05Z"
    });

    /// <summary>A scene with a fleet document and its signature on disk and the signer line on the form.</summary>
    private sealed class Publishing : IDisposable
    {
        private readonly string _folder = Directory.CreateTempSubdirectory("fleet-publish-test-").FullName;
        public StaWindowAdminScene Scene { get; }
        public string Document => Path.Combine(_folder, "fleet.toml");

        public Publishing(bool withGrant = true, string? signature = null, long? stored = null)
        {
            File.WriteAllBytes(Document, Body);
            if (signature != string.Empty) File.WriteAllText(Document + ".sig", signature ?? SshSignatureMaker.File(Key));
            Scene = new StaWindowAdminScene().Enroll(withGrant);
            Scene.Bus.On(Read, _ => stored is { } serial ? StaWindowAdminBus.Ok(Stored(serial)) : StaWindowAdminBus.Fail(404, "Not found."));
            Scene.Bus.On(Publish, _ => StaWindowAdminBus.Ok(Stored(4)));
            Scene.Platform.FleetFilePath = Document;
            Scene.Open();
            Scene.Window.HostSigners.Text = SshSignatureMaker.SignerLine(Key);
        }

        public void Click() => StaWindowAdminScene.ClickAndWait(Scene.Window.FleetPublishButton);

        public void Dispose()
        {
            Scene.Dispose();
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Fact]
    public void AVerifiedDocumentIsPublishedUnchangedAfterTheQuestionAndWindowsHello() => sta.Run(() =>
    {
        using var publishing = new Publishing();
        var scene = publishing.Scene;

        publishing.Click();

        var sent = JsonDocument.Parse(Assert.Single(scene.Bus.RequestsTo(Publish)).Body).RootElement;
        Assert.Equal(4, sent.GetProperty("serial").GetInt64());
        Assert.Equal(Convert.ToBase64String(Body), sent.GetProperty("body").GetString());
        Assert.Equal(SshSignatureMaker.File(Key), sent.GetProperty("signature").GetString());
        Assert.Equal(HostEnrolFile.SignerFingerprint(SshSignatureMaker.SignerLine(Key)), sent.GetProperty("signer_fingerprint").GetString());
        Assert.Equal(FleetPublishLogic.Reason(4), sent.GetProperty("reason").GetString());
        Assert.Equal([(SshSignatureMaker.SignerLine(Key), "chris", "strugglebus-fleet", Body.Length)], scene.Platform.Verified);
        Assert.Contains(scene.Platform.Confirmations, asked => asked.Item1.StartsWith("Publish fleet serial 4 to the bus?", StringComparison.Ordinal));
        Assert.Contains(FleetPublishLogic.HelloPrompt(4), scene.Platform.HelloPrompts);
        Assert.Equal(Visibility.Visible, scene.Window.FleetResultPanel.Visibility);
        Assert.StartsWith("Published fleet serial 4 at ", scene.Window.FleetResult.Text);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void ASignatureThatDoesNotVerifyIsNeverSent() => sta.Run(() =>
    {
        using var publishing = new Publishing();
        publishing.Scene.Platform.Verdict = SshVerdict.Bad;

        publishing.Click();

        Assert.Empty(publishing.Scene.Bus.RequestsTo(Publish));
        Assert.Empty(publishing.Scene.Bus.RequestsTo(Read));
        Assert.Equal(FleetPublishLogic.BadSignature, publishing.Scene.Notice);
    });

    [Fact]
    public void WithoutWindowsOwnSshKeygenNothingIsSent() => sta.Run(() =>
    {
        using var publishing = new Publishing();
        publishing.Scene.Platform.Verdict = SshVerdict.NoTool;

        publishing.Click();

        Assert.Empty(publishing.Scene.Bus.RequestsTo(Publish));
        Assert.Equal(FleetPublishLogic.NoTool, publishing.Scene.Notice);
    });

    [Fact]
    public void ASignatureWithoutTouchAndPinIsRefusedBeforeSshKeygenIsAsked() => sta.Run(() =>
    {
        using var publishing = new Publishing(signature: SshSignatureMaker.File(Key, flags: 0x01));

        publishing.Click();

        Assert.Empty(publishing.Scene.Platform.Verified);
        Assert.Empty(publishing.Scene.Bus.RequestsTo(Publish));
        Assert.Equal(FleetPublishLogic.NoTouchAndPin, publishing.Scene.Notice);
    });

    [Fact]
    public void ASerialTheBusAlreadyHoldsIsRefusedWithoutAsking() => sta.Run(() =>
    {
        using var publishing = new Publishing(stored: 4);

        publishing.Click();

        Assert.Empty(publishing.Scene.Bus.RequestsTo(Publish));
        Assert.DoesNotContain(FleetPublishLogic.HelloPrompt(4), publishing.Scene.Platform.HelloPrompts);
        Assert.Contains("already holds fleet serial 4", publishing.Scene.Notice);
    });

    [Fact]
    public void SayingNoToTheQuestionSendsNothing() => sta.Run(() =>
    {
        using var publishing = new Publishing(stored: 3);
        publishing.Scene.Platform.ConfirmAnswer = false;

        publishing.Click();

        Assert.Empty(publishing.Scene.Bus.RequestsTo(Publish));
        Assert.Contains(publishing.Scene.Platform.Confirmations, asked => asked.Item1.Contains("It replaces serial 3."));
        Assert.Equal(Visibility.Collapsed, publishing.Scene.Window.FleetResultPanel.Visibility);
    });

    [Fact]
    public void AMissingSignatureFileOrNoFileChosenOrNoOperatorAccessStopsAtOnce() => sta.Run(() =>
    {
        using (var missing = new Publishing(signature: string.Empty))
        {
            missing.Click();
            Assert.Equal("No signature was found. It must be beside the document, named fleet.toml.sig.", missing.Scene.Notice);
        }

        using (var cancelled = new Publishing())
        {
            cancelled.Scene.Platform.FleetFilePath = null;
            cancelled.Click();
            Assert.Empty(cancelled.Scene.Platform.Verified);
            Assert.Equal(string.Empty, cancelled.Scene.Notice);
        }

        using var noGrant = new Publishing(withGrant: false);
        noGrant.Click();
        Assert.Equal(FleetPublishLogic.NeedsOperator, noGrant.Scene.Notice);
    });

    [Fact]
    public void AnOversizedSignatureFileIsNotRead() => sta.Run(() =>
    {
        using var publishing = new Publishing(signature: new string('A', SshSignature.MaxLength + 1));

        publishing.Click();

        Assert.Equal(FleetPublishLogic.NotASignature, publishing.Scene.Notice);
    });
}
