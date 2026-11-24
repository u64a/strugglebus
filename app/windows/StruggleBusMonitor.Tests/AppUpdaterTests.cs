using Velopack;

namespace StruggleBusMonitor.Tests;

/// <summary>An update engine that never touches the network, the disk or another process.</summary>
internal sealed class FakeUpdateEngine : IUpdateEngine
{
    public bool IsInstalled { get; set; } = true;
    public string? InstalledVersion { get; set; } = "1.4.0";
    public UpdatePackage? PendingRestart { get; set; }
    public UpdatePackage? Available { get; set; }
    public Exception? CheckFailure { get; set; }
    public Exception? DownloadFailure { get; set; }
    public Exception? ApplyFailure { get; set; }
    public int Checks { get; private set; }
    public List<UpdatePackage> Downloaded { get; } = [];
    public List<UpdatePackage> Restarted { get; } = [];
    public List<UpdatePackage> AppliedAfterExit { get; } = [];

    public Task<UpdatePackage?> CheckAsync()
    {
        Checks++;
        return CheckFailure is null ? Task.FromResult(Available) : Task.FromException<UpdatePackage?>(CheckFailure);
    }

    public Task DownloadAsync(UpdatePackage package, CancellationToken cancellationToken)
    {
        if (DownloadFailure is not null) return Task.FromException(DownloadFailure);
        Downloaded.Add(package);
        return Task.CompletedTask;
    }

    public void ApplyAndRestart(UpdatePackage package) => Restarted.Add(package);

    public void ApplyAfterExit(UpdatePackage package)
    {
        if (ApplyFailure is not null) throw ApplyFailure;
        AppliedAfterExit.Add(package);
    }
}

internal sealed class RecordingProgress : IProgress<UpdateStatus>
{
    public List<UpdateStatus> Reports { get; } = [];
    public void Report(UpdateStatus value) => Reports.Add(value);
}

public sealed class AppUpdaterTests
{
    private static readonly UpdatePackage Newer = new("1.5.0");

    [Fact]
    public async Task ACopyThatWasNotInstalledCannotUpdateItself()
    {
        var engine = new FakeUpdateEngine { IsInstalled = false, Available = Newer };
        var updater = new AppUpdater(engine);

        var status = await updater.CheckAndDownloadAsync(null, CancellationToken.None);

        Assert.False(updater.CanUpdate);
        Assert.Equal(new UpdateStatus(UpdateState.NotInstalled), status);
        Assert.Equal(0, engine.Checks);
    }

    [Fact]
    public async Task WithoutAnEngineNothingIsCheckedOrApplied()
    {
        var updater = new AppUpdater(null);

        Assert.False(updater.CanUpdate);
        Assert.Equal(UpdateState.NotInstalled, (await updater.CheckAndDownloadAsync(null, CancellationToken.None)).State);
        updater.RestartIntoUpdate();
        updater.ApplyOnExit();
    }

    [Fact]
    public async Task UpToDateWhenTheEngineFindsNothingNewer()
    {
        var engine = new FakeUpdateEngine();
        var updater = new AppUpdater(engine);
        var progress = new RecordingProgress();

        var status = await updater.CheckAndDownloadAsync(progress, CancellationToken.None);

        Assert.Equal(new UpdateStatus(UpdateState.UpToDate), status);
        Assert.Empty(progress.Reports);
        Assert.Empty(engine.Downloaded);
    }

    [Fact]
    public async Task ANewerVersionIsDownloadedAndWaitsForARestart()
    {
        var engine = new FakeUpdateEngine { Available = Newer };
        var updater = new AppUpdater(engine);
        var progress = new RecordingProgress();

        var status = await updater.CheckAndDownloadAsync(progress, CancellationToken.None);

        Assert.Equal(new UpdateStatus(UpdateState.ReadyToRestart, "1.5.0"), status);
        Assert.Equal([new UpdateStatus(UpdateState.Downloading, "1.5.0")], progress.Reports);
        Assert.Equal([Newer], engine.Downloaded);
        Assert.Empty(engine.Restarted);
        Assert.Empty(engine.AppliedAfterExit);
    }

    [Fact]
    public async Task AManualCheckWithDownloadsOffOnlyReportsTheVersion()
    {
        var engine = new FakeUpdateEngine { Available = Newer };
        var updater = new AppUpdater(engine);
        var progress = new RecordingProgress();

        var status = await updater.CheckAndDownloadAsync(progress, CancellationToken.None, download: false);
        updater.RestartIntoUpdate();
        updater.ApplyOnExit();

        Assert.Equal(new UpdateStatus(UpdateState.Available, "1.5.0"), status);
        Assert.Empty(progress.Reports);
        Assert.Empty(engine.Downloaded);
        Assert.Empty(engine.Restarted);
        Assert.Empty(engine.AppliedAfterExit);
    }

    [Fact]
    public async Task ADownloadedUpdateIsNotCheckedOrDownloadedAgain()
    {
        var engine = new FakeUpdateEngine { Available = Newer };
        var updater = new AppUpdater(engine);
        await updater.CheckAndDownloadAsync(null, CancellationToken.None);
        engine.Available = new UpdatePackage("1.6.0");

        var again = await updater.CheckAndDownloadAsync(null, CancellationToken.None);

        Assert.Equal(new UpdateStatus(UpdateState.ReadyToRestart, "1.5.0"), again);
        Assert.Equal(1, engine.Checks);
        Assert.Single(engine.Downloaded);
    }

    [Fact]
    public async Task AnUpdateDownloadedByAnEarlierRunOnlyNeedsARestart()
    {
        var pending = new UpdatePackage("1.4.9");
        var engine = new FakeUpdateEngine { PendingRestart = pending, Available = Newer };
        var updater = new AppUpdater(engine);

        var status = await updater.CheckAndDownloadAsync(null, CancellationToken.None);
        updater.RestartIntoUpdate();

        Assert.Equal(new UpdateStatus(UpdateState.ReadyToRestart, "1.4.9"), status);
        Assert.Equal(0, engine.Checks);
        Assert.Equal([pending], engine.Restarted);
    }

    [Fact]
    public async Task AFailedCheckIsReportedNotThrown()
    {
        var engine = new FakeUpdateEngine { CheckFailure = new HttpRequestException("GitHub is unreachable.") };
        var updater = new AppUpdater(engine);

        var status = await updater.CheckAndDownloadAsync(null, CancellationToken.None);

        Assert.Equal(new UpdateStatus(UpdateState.Failed, Detail: "GitHub is unreachable."), status);
    }

    [Fact]
    public async Task AFailedDownloadIsReportedAndNothingIsReadyToInstall()
    {
        var engine = new FakeUpdateEngine { Available = Newer, DownloadFailure = new InvalidDataException("Checksum mismatch.") };
        var updater = new AppUpdater(engine);
        var progress = new RecordingProgress();

        var status = await updater.CheckAndDownloadAsync(progress, CancellationToken.None);
        updater.RestartIntoUpdate();
        updater.ApplyOnExit();

        Assert.Equal(new UpdateStatus(UpdateState.Failed, Detail: "Checksum mismatch."), status);
        Assert.Equal([new UpdateStatus(UpdateState.Downloading, "1.5.0")], progress.Reports);
        Assert.Empty(engine.Restarted);
        Assert.Empty(engine.AppliedAfterExit);
    }

    [Fact]
    public async Task AFailureDoesNotBlockTheNextCheck()
    {
        var engine = new FakeUpdateEngine { Available = Newer, DownloadFailure = new IOException("Disk full.") };
        var updater = new AppUpdater(engine);
        await updater.CheckAndDownloadAsync(null, CancellationToken.None);
        engine.DownloadFailure = null;

        var retried = await updater.CheckAndDownloadAsync(null, CancellationToken.None);

        Assert.Equal(UpdateState.ReadyToRestart, retried.State);
        Assert.Equal(2, engine.Checks);
    }

    [Fact]
    public async Task CancellationIsPassedOnNotReportedAsAFailure()
    {
        var engine = new FakeUpdateEngine { Available = Newer, DownloadFailure = new OperationCanceledException() };
        var updater = new AppUpdater(engine);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => updater.CheckAndDownloadAsync(null, CancellationToken.None));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => updater.CheckAndDownloadAsync(null, cancelled.Token));
        Assert.Equal(1, engine.Checks);
    }

    [Fact]
    public async Task RestartIntoUpdate_InstallsTheDownloadedVersion()
    {
        var engine = new FakeUpdateEngine { Available = Newer };
        var updater = new AppUpdater(engine);

        updater.RestartIntoUpdate();
        Assert.Empty(engine.Restarted);
        await updater.CheckAndDownloadAsync(null, CancellationToken.None);
        updater.RestartIntoUpdate();

        Assert.Equal([Newer], engine.Restarted);
    }

    [Fact]
    public async Task ApplyOnExit_InstallsQuietlyAndSurvivesAFailure()
    {
        var engine = new FakeUpdateEngine { Available = Newer };
        var updater = new AppUpdater(engine);

        updater.ApplyOnExit();
        Assert.Empty(engine.AppliedAfterExit);
        await updater.CheckAndDownloadAsync(null, CancellationToken.None);
        updater.ApplyOnExit();
        engine.ApplyFailure = new InvalidOperationException("Update.exe is missing.");
        updater.ApplyOnExit();

        Assert.Equal([Newer], engine.AppliedAfterExit);
    }

    [Fact]
    public void CurrentVersion_IsTheInstalledVersionWhenInstalled() =>
        Assert.Equal("1.4.0", new AppUpdater(new FakeUpdateEngine()).CurrentVersion);

    [Fact]
    public void CurrentVersion_FallsBackToTheBuildVersionWithoutItsCommit()
    {
        var version = new AppUpdater(new FakeUpdateEngine { IsInstalled = false }).CurrentVersion;

        Assert.NotEmpty(version);
        Assert.DoesNotContain('+', version);
        Assert.Equal(version, new AppUpdater(null).CurrentVersion);
    }

    [Fact]
    public async Task TheRealUpdaterTreatsATestRunAsNotInstalled()
    {
        var updater = new AppUpdater();

        Assert.False(updater.CanUpdate);
        Assert.Equal(UpdateState.NotInstalled, (await updater.CheckAndDownloadAsync(null, CancellationToken.None)).State);
        Assert.DoesNotContain('+', updater.CurrentVersion);
        updater.RestartIntoUpdate();
        updater.ApplyOnExit();
    }
}

public sealed class VelopackEngineTests
{
    private static VelopackAsset Asset(string version) => new()
    {
        PackageId = "StruggleBusMonitor",
        Version = SemanticVersion.Parse(version),
        FileName = $"StruggleBusMonitor-{version}-full.nupkg"
    };

    [Fact]
    public void FromAsset_CarriesTheVersionAndTheAssetToInstall()
    {
        var asset = Asset("1.5.0");

        var package = VelopackEngine.FromAsset(asset);

        Assert.Equal("1.5.0", package?.Version);
        Assert.Same(asset, package?.Asset);
        Assert.Null(package?.Source);
        Assert.Null(VelopackEngine.FromAsset(null));
    }

    [Fact]
    public void FromUpdate_TargetsTheFullRelease()
    {
        var target = Asset("1.6.0-beta.1");
        var update = new UpdateInfo(target, false);

        var package = VelopackEngine.FromUpdate(update);

        Assert.Equal("1.6.0-beta.1", package?.Version);
        Assert.Same(target, package?.Asset);
        Assert.Same(update, package?.Source);
        Assert.Null(VelopackEngine.FromUpdate(null));
    }
}
