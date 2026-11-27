using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using Velopack;
using Velopack.Logging;
using Velopack.Sources;

namespace StruggleBusMonitor;

/// <summary>One release of this app as its tag names it: <c>windows/v1.7.5</c>.</summary>
internal sealed record AppReleaseTag(string Name, Version Version)
{
    /// <summary>The version as the release's own files write it: 1.7.5.</summary>
    public string Text => Version.ToString(3);
}

/// <summary>
/// Reads this app's release tags. The repository also holds the bus's releases, under
/// <c>bus/v</c> tags, and those are never this app's.
/// </summary>
internal static partial class AppReleaseTags
{
    public const string Prefix = "windows/v";

    [GeneratedRegex(@"^refs/tags/(windows/v(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4}))\z")]
    private static partial Regex Ref();

    /// <summary>The tag a ref names, or null when it is not exactly <c>windows/vX.Y.Z</c>.</summary>
    internal static AppReleaseTag? FromRef(string? reference)
    {
        if (reference is null || Ref().Match(reference) is not { Success: true } match) return null;
        int Part(int group) => int.Parse(match.Groups[group].Value);
        return new AppReleaseTag(match.Groups[1].Value, new Version(Part(2), Part(3), Part(4)));
    }

    /// <summary>The refs in one answer from GitHub's list of matching tags.</summary>
    internal static IReadOnlyList<string?> RefsIn(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.EnumerateArray().Select(RefOf).ToList();
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            throw new InvalidOperationException(AppReleaseSource.Unreadable, error);
        }
    }

    private static string? RefOf(JsonElement entry) =>
        entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("ref", out var reference) && reference.ValueKind == JsonValueKind.String
            ? reference.GetString()
            : null;

    /// <summary>This app's release tags, newest version first. Anything else among the refs is left out.</summary>
    internal static IReadOnlyList<AppReleaseTag> NewestFirst(IEnumerable<string?> references) =>
        references.Select(FromRef).OfType<AppReleaseTag>().DistinctBy(tag => tag.Version).OrderByDescending(tag => tag.Version).ToList();
}

/// <summary>
/// Where the app finds its updates: the releases of one GitHub repository whose tags begin
/// <c>windows/v</c>. Releases are found by tag, not from the repository's list of newest
/// releases, because the bus publishes in the same repository and enough bus releases would push
/// every app release off that list, which would look the same as being up to date.
///
/// One request goes to GitHub's API, for the tags. The files come from the release's ordinary
/// download address, which GitHub does not count against the hourly limit for requests that are
/// not signed in. A tag whose release is not published yet (a release is tagged, built, signed
/// and only then published) answers "not found" and is passed over.
///
/// Nothing here decides whether an update is trusted; see <see cref="UpdateTrust"/>.
/// </summary>
internal sealed class AppReleaseSource(string repository, IFileDownloader downloader) : IUpdateSource
{
    public const int TagsInOneAnswer = 100;

    /// <summary>The most answers read for tags. More tags than these hold is reported, never ignored.</summary>
    public const int TagAnswers = 10;

    /// <summary>How many of the newest releases are read, so a copy a few versions behind can still take the small update packages.</summary>
    public const int ReleasesRead = 5;

    private const double MinutesForAList = 1;
    private const double MinutesForAFile = 30;

    public const string Limited = "GitHub is limiting requests from this network, so the app could not look for updates. It will look again later.";
    public const string Unreadable = "GitHub's list of this app's releases could not be read.";
    public const string TooManyTags = "There are more app release tags than the app reads, so it cannot tell which release is newest.";
    public const string NothingPublished = "The newest app release tags have no published release, so the app cannot tell whether it is up to date.";

    private static readonly Dictionary<string, string> ApiHeaders = new() { ["Accept"] = "application/vnd.github+json" };

    public async Task<VelopackAssetFeed> GetReleaseFeed(
        IVelopackLogger logger, string? appId, string channel, Guid? stagingId = null, VelopackAsset? latestLocalRelease = null)
    {
        var tags = AppReleaseTags.NewestFirst(await TagRefsAsync());
        var assets = new List<VelopackAsset>();
        var published = 0;
        foreach (var tag in tags.Take(ReleasesRead))
        {
            if (await FilesOfAsync(tag, channel) is not { } files) continue;
            published++;
            assets.AddRange(files);
        }

        if (published == 0 && tags.Count > ReleasesRead) throw new InvalidOperationException(NothingPublished);
        return new VelopackAssetFeed { Assets = [.. assets] };
    }

    public Task DownloadReleaseEntry(
        IVelopackLogger logger, VelopackAsset releaseEntry, string localFile, Action<int> progress, CancellationToken cancelToken = default) =>
        downloader.DownloadFile(
            FileUrl(AppReleaseTags.Prefix + releaseEntry.Version, releaseEntry.FileName), localFile, progress, null, MinutesForAFile, cancelToken);

    /// <summary>Every ref GitHub lists under the app's tag prefix.</summary>
    private async Task<List<string?>> TagRefsAsync()
    {
        var references = new List<string?>();
        for (var answer = 1; answer <= TagAnswers; answer++)
        {
            var listed = AppReleaseTags.RefsIn(await ApiAsync(TagsUrl(answer)));
            references.AddRange(listed);
            if (listed.Count < TagsInOneAnswer) return references;
        }

        throw new InvalidOperationException(TooManyTags);
    }

    private async Task<string> ApiAsync(string url)
    {
        try
        {
            return await downloader.DownloadString(url, ApiHeaders, MinutesForAList);
        }
        catch (HttpRequestException error) when (error.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
        {
            throw new InvalidOperationException(Limited, error);
        }
    }

    /// <summary>
    /// The files one release lists for this channel, or null when the tag has no published
    /// release. A file listed under any other version than the tag's is left out.
    /// </summary>
    private async Task<IReadOnlyList<VelopackAsset>?> FilesOfAsync(AppReleaseTag tag, string channel)
    {
        string listed;
        try
        {
            listed = await downloader.DownloadString(FileUrl(tag.Name, $"releases.{channel}.json"), null, MinutesForAList);
        }
        catch (HttpRequestException error) when (error.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        return VelopackAssetFeed.FromJson(listed).Assets.Where(asset => asset.Version?.ToString() == tag.Text).ToList();
    }

    internal string TagsUrl(int answer) =>
        $"https://api.github.com/repos/{repository}/git/matching-refs/tags/{AppReleaseTags.Prefix}?per_page={TagsInOneAnswer}&page={answer}";

    internal string FileUrl(string tag, string file) =>
        $"https://github.com/{repository}/releases/download/{tag}/{Uri.EscapeDataString(file)}";
}
