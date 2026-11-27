using System.Net;
using System.Net.Http;
using Velopack;
using Velopack.Sources;

namespace StruggleBusMonitor.Tests;

/// <summary>GitHub as the update source sees it: addresses and what each answers. Nothing touches the network.</summary>
internal sealed class FakeGitHub : IFileDownloader
{
    public Dictionary<string, string> Answers { get; } = [];
    public Dictionary<string, HttpStatusCode> Refusals { get; } = [];
    public List<string> Asked { get; } = [];
    public List<(string Url, string File)> Saved { get; } = [];
    public IDictionary<string, string>? LastHeaders { get; private set; }

    public Task<string> DownloadString(string url, IDictionary<string, string>? headers = null, double timeout = 30)
    {
        Asked.Add(url);
        LastHeaders = headers;
        if (Refusals.TryGetValue(url, out var status)) throw new HttpRequestException("refused", null, status);
        return Answers.TryGetValue(url, out var answer)
            ? Task.FromResult(answer)
            : throw new HttpRequestException("not found", null, HttpStatusCode.NotFound);
    }

    public Task DownloadFile(
        string url, string targetFile, Action<int> progress, IDictionary<string, string>? headers = null, double timeout = 30,
        CancellationToken cancelToken = default)
    {
        Saved.Add((url, targetFile));
        return Task.CompletedTask;
    }

    public Task<byte[]> DownloadBytes(string url, IDictionary<string, string>? headers = null, double timeout = 30) =>
        throw new NotSupportedException();
}

/// <summary>Which tags are this app's releases.</summary>
public sealed class AppReleaseTagsTests
{
    [Theory]
    [InlineData("refs/tags/windows/v1.7.5", "windows/v1.7.5", "1.7.5")]
    [InlineData("refs/tags/windows/v0.0.0", "windows/v0.0.0", "0.0.0")]
    [InlineData("refs/tags/windows/v12.345.67890", "windows/v12.345.67890", "12.345.67890")]
    public void AnAppReleaseTagIsExactlyThePrefixAndThreeNumbers(string reference, string name, string version)
    {
        var tag = AppReleaseTags.FromRef(reference);

        Assert.Equal((name, version), (tag?.Name, tag?.Text));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("refs/tags/bus/v0.2.74")]
    [InlineData("refs/tags/v1.7.5")]
    [InlineData("refs/heads/windows/v1.7.5")]
    [InlineData("refs/tags/windows/v1.7")]
    [InlineData("refs/tags/windows/v1.7.5.1")]
    [InlineData("refs/tags/windows/v1.7.5-beta")]
    [InlineData("refs/tags/windows/v01.7.5")]
    [InlineData("refs/tags/windows/v1.7.123456")]
    [InlineData("refs/tags/windows/v1.7.5\n")]
    [InlineData("refs/tags/windows/v1.7.5/extra")]
    public void AnythingElseIsNotAnAppRelease(string? reference) => Assert.Null(AppReleaseTags.FromRef(reference));

    [Fact]
    public void TagsAreOrderedByVersionNotByNameAndOthersAreLeftOut()
    {
        var tags = AppReleaseTags.NewestFirst(
            ["refs/tags/windows/v1.7.9", "refs/tags/windows/v1.10.0", null, "refs/tags/windows/vjunk", "refs/tags/windows/v1.7.10", "refs/tags/windows/v1.7.9"]);

        Assert.Equal(["windows/v1.10.0", "windows/v1.7.10", "windows/v1.7.9"], tags.Select(tag => tag.Name));
    }

    [Fact]
    public void RefsAreReadFromGitHubsAnswerAndAnEntryWithoutOneIsNoRef()
    {
        var refs = AppReleaseTags.RefsIn("""[{"ref":"refs/tags/windows/v1.7.5","object":{}},{"ref":7},{},"text"]""");

        Assert.Equal(["refs/tags/windows/v1.7.5", null, null, null], refs);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"message":"Not Found"}""")]
    public void AnAnswerThatIsNotAListOfRefsIsAProblemNotAnEmptyList(string answer)
    {
        var error = Assert.Throws<InvalidOperationException>(() => AppReleaseTags.RefsIn(answer));

        Assert.Equal(AppReleaseSource.Unreadable, error.Message);
    }
}

/// <summary>How the app finds its own releases in a repository that also holds the bus's.</summary>
public sealed class AppReleaseSourceTests
{
    private const string Repository = "owner/repo";
    private const string Channel = "win-x64";

    private readonly FakeGitHub _gitHub = new();
    private readonly AppReleaseSource _source;

    public AppReleaseSourceTests() => _source = new AppReleaseSource(Repository, _gitHub);

    private static string Refs(IEnumerable<string> tags) =>
        "[" + string.Join(",", tags.Select(tag => $$"""{"ref":"refs/tags/{{tag}}"}""")) + "]";

    private void Tags(params string[] tags) => _gitHub.Answers[_source.TagsUrl(1)] = Refs(tags);

    private static string Entry(string version, string kind) =>
        $$"""{"PackageId":"NZCypher819.StruggleBusMonitor","Version":"{{version}}","Type":"{{kind}}","FileName":"NZCypher819.StruggleBusMonitor-{{version}}-win-x64-{{kind.ToLowerInvariant()}}.nupkg","SHA1":"A","SHA256":"B","Size":1}""";

    /// <summary>A published release for <paramref name="tag"/> listing a full and a small package for each version given.</summary>
    private void Published(string tag, params string[] versions) =>
        _gitHub.Answers[_source.FileUrl(tag, $"releases.{Channel}.json")] =
            $$"""{"Assets":[{{string.Join(",", versions.SelectMany(version => new[] { Entry(version, "Full"), Entry(version, "Delta") }))}}]}""";

    private async Task<VelopackAsset[]> FeedAsync() => (await _source.GetReleaseFeed(null!, "app", Channel)).Assets;

    [Fact]
    public async Task TheFeedHoldsTheAppsReleasesAndNothingOfTheBuss()
    {
        Tags("windows/v1.7.4", "windows/v1.7.5", "windows/v1.7.5-junk");
        Published("windows/v1.7.4", "1.7.4");
        Published("windows/v1.7.5", "1.7.5");

        var assets = await FeedAsync();

        Assert.Equal(["1.7.5", "1.7.5", "1.7.4", "1.7.4"], assets.Select(asset => asset.Version.ToString()));
        Assert.Equal(
            [
                "https://api.github.com/repos/owner/repo/git/matching-refs/tags/windows/v?per_page=100&page=1",
                "https://github.com/owner/repo/releases/download/windows/v1.7.5/releases.win-x64.json",
                "https://github.com/owner/repo/releases/download/windows/v1.7.4/releases.win-x64.json"
            ],
            _gitHub.Asked);
    }

    [Fact]
    public async Task ATagWhoseReleaseIsNotPublishedYetIsPassedOver()
    {
        Tags("windows/v1.7.4", "windows/v1.7.5");
        Published("windows/v1.7.4", "1.7.4");

        Assert.All(await FeedAsync(), asset => Assert.Equal("1.7.4", asset.Version.ToString()));
    }

    [Fact]
    public async Task ARepositoryWithNoAppReleasesYetIsUpToDate()
    {
        Tags();
        Assert.Empty(await FeedAsync());

        Tags("windows/v1.7.5");
        Assert.Empty(await FeedAsync());
    }

    [Fact]
    public async Task OnlyTheNewestFewReleasesAreRead()
    {
        Tags([.. Enumerable.Range(0, 8).Select(patch => $"windows/v1.0.{patch}")]);
        foreach (var patch in Enumerable.Range(0, 8)) Published($"windows/v1.0.{patch}", $"1.0.{patch}");

        var versions = (await FeedAsync()).Select(asset => asset.Version.ToString()).Distinct();

        Assert.Equal(["1.0.7", "1.0.6", "1.0.5", "1.0.4", "1.0.3"], versions);
    }

    [Fact]
    public async Task NewestTagsWithNoReleaseAtAllAreAProblemNotUpToDate()
    {
        Tags([.. Enumerable.Range(0, 6).Select(patch => $"windows/v1.0.{patch}")]);
        Published("windows/v1.0.0", "1.0.0");

        var error = await Assert.ThrowsAsync<InvalidOperationException>(FeedAsync);

        Assert.Equal(AppReleaseSource.NothingPublished, error.Message);
    }

    [Fact]
    public async Task AFileListedUnderAnotherVersionThanItsTagIsLeftOut()
    {
        Tags("windows/v1.7.5");
        Published("windows/v1.7.5", "1.7.5", "9.9.9");

        Assert.All(await FeedAsync(), asset => Assert.Equal("1.7.5", asset.Version.ToString()));
    }

    [Fact]
    public async Task TagsAreReadAcrossAnswersUntilAShortOne()
    {
        _gitHub.Answers[_source.TagsUrl(1)] = Refs(Enumerable.Range(0, 100).Select(patch => $"windows/v1.0.{patch}"));
        _gitHub.Answers[_source.TagsUrl(2)] = Refs(["windows/v2.0.0"]);
        Published("windows/v2.0.0", "2.0.0");

        Assert.Contains(await FeedAsync(), asset => asset.Version.ToString() == "2.0.0");
    }

    [Fact]
    public async Task MoreTagsThanTheAppReadsIsAProblem()
    {
        foreach (var answer in Enumerable.Range(1, AppReleaseSource.TagAnswers))
        {
            _gitHub.Answers[_source.TagsUrl(answer)] = Refs(Enumerable.Range(0, 100).Select(patch => $"windows/v{answer}.0.{patch}"));
        }

        var error = await Assert.ThrowsAsync<InvalidOperationException>(FeedAsync);

        Assert.Equal(AppReleaseSource.TooManyTags, error.Message);
        Assert.Equal(AppReleaseSource.TagAnswers, _gitHub.Asked.Count);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task BeingLimitedByGitHubIsSaidInPlainWords(HttpStatusCode status)
    {
        _gitHub.Refusals[_source.TagsUrl(1)] = status;

        var error = await Assert.ThrowsAsync<InvalidOperationException>(FeedAsync);

        Assert.Equal(AppReleaseSource.Limited, error.Message);
    }

    [Fact]
    public async Task AnyOtherFailureIsAFailureNotUpToDate()
    {
        _gitHub.Refusals[_source.TagsUrl(1)] = HttpStatusCode.BadGateway;
        await Assert.ThrowsAsync<HttpRequestException>(FeedAsync);

        _gitHub.Refusals.Clear();
        Tags("windows/v1.7.5");
        _gitHub.Refusals[_source.FileUrl("windows/v1.7.5", $"releases.{Channel}.json")] = HttpStatusCode.BadGateway;
        await Assert.ThrowsAsync<HttpRequestException>(FeedAsync);
    }

    [Fact]
    public async Task TheTagsAreAskedOfGitHubsApiWithItsMediaType()
    {
        Tags();
        await FeedAsync();

        Assert.Equal("application/vnd.github+json", _gitHub.LastHeaders?["Accept"]);
    }

    [Fact]
    public async Task APackageIsDownloadedFromItsOwnVersionsRelease()
    {
        Tags("windows/v1.7.5");
        Published("windows/v1.7.5", "1.7.5");
        var full = (await FeedAsync()).First(asset => asset.Type == VelopackAssetType.Full);

        await _source.DownloadReleaseEntry(null!, full, @"C:\packages\file.nupkg", _ => { });

        Assert.Equal(
            [("https://github.com/owner/repo/releases/download/windows/v1.7.5/NZCypher819.StruggleBusMonitor-1.7.5-win-x64-full.nupkg", @"C:\packages\file.nupkg")],
            _gitHub.Saved);
    }

    [Fact]
    public void TheAppReadsItsReleasesFromTheProjectsRepository()
    {
        Assert.Equal("u64a/strugglebus", AppUpdater.Repository);
        Assert.Equal("https://github.com/u64a/strugglebus", AppUpdater.ReleasesUrl);
    }
}
