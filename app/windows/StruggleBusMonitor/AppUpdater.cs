using System.IO;
using System.Reflection;
using Velopack;
using Velopack.Locators;
using Velopack.Sources;

namespace StruggleBusMonitor;

public enum UpdateState
{
    /// <summary>Running from a ZIP or a dev build; only an installed copy can update itself.</summary>
    NotInstalled,
    UpToDate,
    /// <summary>A newer version exists but has not been downloaded; only a manual check with automatic updates off.</summary>
    Available,
    Downloading,
    ReadyToRestart,
    Failed
}

public sealed record UpdateStatus(UpdateState State, string? Version = null, string? Detail = null);

/// <summary>
/// A version the update engine found or already downloaded. The Velopack objects ride along for the
/// engine that produced them; the updater itself only reads <see cref="Version"/>.
/// </summary>
internal sealed record UpdatePackage(string Version, VelopackAsset? Asset = null, UpdateInfo? Source = null);

/// <summary>What the updater needs from the installer framework: look, download, install. Nothing here decides anything.</summary>
internal interface IUpdateEngine
{
    bool IsInstalled { get; }
    string? InstalledVersion { get; }

    /// <summary>An update downloaded by an earlier run that only needs a restart.</summary>
    UpdatePackage? PendingRestart { get; }

    /// <summary>The newest release, or null when this copy is already on it. Uses the network.</summary>
    Task<UpdatePackage?> CheckAsync();
    Task DownloadAsync(UpdatePackage package, CancellationToken cancellationToken);

    /// <summary>
    /// Why the downloaded package must not be installed, or null when its files are signed by
    /// this app's publisher. See <see cref="UpdateTrust"/>.
    /// </summary>
    string? Problem(UpdatePackage package);

    /// <summary>Removes a downloaded package so that nothing installs it later.</summary>
    void Discard(UpdatePackage package);

    /// <summary>Closes the app, installs the package and starts the new version with <paramref name="arguments"/>.</summary>
    void ApplyAndRestart(UpdatePackage package, string[] arguments);

    /// <summary>Installs the package once this process has exited, without starting the app again.</summary>
    void ApplyAfterExit(UpdatePackage package);
}

/// <summary>The real engine: Velopack against this app's public GitHub releases.</summary>
internal sealed class VelopackEngine(UpdateManager manager) : IUpdateEngine
{
    public bool IsInstalled => manager.IsInstalled;
    public string? InstalledVersion => manager.CurrentVersion?.ToString();
    public UpdatePackage? PendingRestart => FromAsset(manager.UpdatePendingRestart);

    public async Task<UpdatePackage?> CheckAsync() => FromUpdate(await manager.CheckForUpdatesAsync());

    public Task DownloadAsync(UpdatePackage package, CancellationToken cancellationToken) =>
        manager.DownloadUpdatesAsync(package.Source!, null, cancellationToken);

    public string? Problem(UpdatePackage package) => PackageProblem(PackagePath(package), UpdateTrust.Problem);

    public void Discard(UpdatePackage package)
    {
        if (PackagePath(package) is { } path) File.Delete(path);
    }

    private static string? PackagePath(UpdatePackage package) =>
        VelopackLocator.Current.PackagesDir is { } folder ? Path.Combine(folder, package.Asset!.FileName) : null;

    /// <summary>A package that cannot be found cannot be checked, so it is refused.</summary>
    internal static string? PackageProblem(string? path, Func<string, string?> check) =>
        path is not null && File.Exists(path) ? check(path) : "The update was not installed: its file could not be found to check its signature.";

    public void ApplyAndRestart(UpdatePackage package, string[] arguments) => manager.ApplyUpdatesAndRestart(package.Asset!, arguments);

    public void ApplyAfterExit(UpdatePackage package) =>
        manager.WaitExitThenApplyUpdates(package.Asset!, silent: true, restart: false);

    internal static UpdatePackage? FromAsset(VelopackAsset? asset) =>
        asset is null ? null : new UpdatePackage(asset.Version.ToString(), asset);

    internal static UpdatePackage? FromUpdate(UpdateInfo? update) =>
        update is null ? null : new UpdatePackage(update.TargetFullRelease.Version.ToString(), update.TargetFullRelease, update);
}

/// <summary>
/// Self-update from the public GitHub releases. Checks and downloads in the background; nothing is
/// applied until the operator restarts or closes the app. With automatic updates off (see
/// <see cref="AppSettings.AutoUpdate"/>) the window only calls this when the operator asks.
/// </summary>
public sealed class AppUpdater
{
    /// <summary>The repository whose <c>windows/v</c> releases are this app's. See <see cref="AppReleaseSource"/>.</summary>
    public const string Repository = "u64a/strugglebus";

    public const string ReleasesUrl = "https://github.com/" + Repository;

    private readonly IUpdateEngine? _engine;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private UpdatePackage? _ready;

    public AppUpdater() : this(CreateEngine())
    {
    }

    /// <summary>For tests: the decisions below run against <paramref name="engine"/> instead of Velopack.</summary>
    internal AppUpdater(IUpdateEngine? engine) => _engine = engine;

    private static IUpdateEngine? CreateEngine()
    {
        try { return new VelopackEngine(new UpdateManager(new AppReleaseSource(Repository, new HttpClientFileDownloader()))); }
        catch (Exception) { return null; }
    }

    public bool CanUpdate => _engine is { IsInstalled: true };

    public string CurrentVersion => InstalledVersion() ?? DisplayVersion(
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    private string? InstalledVersion() => CanUpdate ? _engine!.InstalledVersion : null;

    /// <summary>Drops the "+commit" build metadata the SDK appends to the informational version.</summary>
    internal static string DisplayVersion(string? informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion)) return "dev";
        var plus = informationalVersion.IndexOf('+');
        return plus < 0 ? informationalVersion : informationalVersion[..plus];
    }

    /// <summary>Looks for a newer version. With <paramref name="download"/> off it only reports that one exists.</summary>
    public async Task<UpdateStatus> CheckAndDownloadAsync(IProgress<UpdateStatus>? progress, CancellationToken cancellationToken, bool download = true)
    {
        if (!CanUpdate) return new UpdateStatus(UpdateState.NotInstalled);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return ReadyStatus(_engine!) ?? await FindUpdateAsync(_engine!, progress, download, cancellationToken);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error)
        {
            return new UpdateStatus(UpdateState.Failed, Detail: error.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The status when an update is already downloaded, by this run or an earlier one.</summary>
    private UpdateStatus? ReadyStatus(IUpdateEngine engine)
    {
        _ready ??= Accept(engine, engine.PendingRestart);
        return _ready is null ? null : new UpdateStatus(UpdateState.ReadyToRestart, _ready.Version);
    }

    /// <summary>
    /// Lets a downloaded package through only if its signatures check out. One that fails is
    /// removed, so that nothing installs it later, and the reason is reported as a failed update.
    /// </summary>
    private static UpdatePackage? Accept(IUpdateEngine engine, UpdatePackage? package)
    {
        if (package is null || engine.Problem(package) is not { } problem) return package;
        engine.Discard(package);
        throw new InvalidOperationException(problem);
    }

    /// <summary>
    /// At startup, installs an update that an earlier run downloaded, after checking it. Each
    /// version is tried this way once: <paramref name="lastAttempt"/> is the version tried before
    /// and <paramref name="remember"/> records this one, so an install that keeps failing cannot
    /// restart the app in a loop. It is still installed on exit or from Settings.
    /// </summary>
    public void ApplyPendingAtStartup(string? lastAttempt, Action<string> remember, params string[] restartArguments)
    {
        if (!CanUpdate) return;
        try
        {
            if (Accept(_engine!, _engine!.PendingRestart) is not { } pending || pending.Version == lastAttempt) return;
            remember(pending.Version);
            _engine.ApplyAndRestart(pending, restartArguments);
        }
        catch (Exception) { /* The window reports it at the next check. */ }
    }

    private async Task<UpdateStatus> FindUpdateAsync(IUpdateEngine engine, IProgress<UpdateStatus>? progress, bool download, CancellationToken cancellationToken)
    {
        var update = await engine.CheckAsync();
        if (update is null) return new UpdateStatus(UpdateState.UpToDate);
        if (!download) return new UpdateStatus(UpdateState.Available, update.Version);

        progress?.Report(new UpdateStatus(UpdateState.Downloading, update.Version));
        await engine.DownloadAsync(update, cancellationToken);
        _ready = Accept(engine, update);
        return new UpdateStatus(UpdateState.ReadyToRestart, update.Version);
    }

    /// <summary>Closes the app, installs the downloaded update and starts the new version with <paramref name="arguments"/>.</summary>
    public void RestartIntoUpdate(params string[] arguments)
    {
        if (_engine is not null && _ready is not null) _engine.ApplyAndRestart(_ready, arguments);
    }

    /// <summary>Installs the downloaded update after this process exits, without relaunching.</summary>
    public void ApplyOnExit()
    {
        if (_engine is null || _ready is null) return;
        try { _engine.ApplyAfterExit(_ready); }
        catch (Exception) { /* The update stays downloaded and is offered again next launch. */ }
    }
}
