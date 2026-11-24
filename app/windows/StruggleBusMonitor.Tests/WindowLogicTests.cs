using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Input;

namespace StruggleBusMonitor.Tests;

public class WindowLogicTests
{
    private static readonly Rect Screen = new(0, 0, 1920, 1080);

    [Fact]
    public void ASavedPlacementOnTheScreenIsRestored()
    {
        Assert.Equal(new Rect(100, 50, 1280, 820), WindowLogic.RestoredBounds(100, 50, 1280, 820, Screen, 980, 620));
    }

    [Theory]
    [InlineData(null, 50d, 1280d, 820d)]
    [InlineData(100d, null, 1280d, 820d)]
    [InlineData(100d, 50d, null, 820d)]
    [InlineData(100d, 50d, 1280d, null)]
    public void NothingIsRestoredUntilEveryValueWasSaved(double? left, double? top, double? width, double? height)
    {
        Assert.Null(WindowLogic.RestoredBounds(left, top, width, height, Screen, 980, 620));
    }

    [Theory]
    [InlineData(979d, 820d)]
    [InlineData(1280d, 619d)]
    public void APlacementSmallerThanTheWindowAllowsIsIgnored(double width, double height)
    {
        Assert.Null(WindowLogic.RestoredBounds(100, 50, width, height, Screen, 980, 620));
    }

    [Theory]
    [InlineData(1841d, 50d, false)]   // only 79 px of the left edge would show
    [InlineData(1839d, 50d, true)]
    [InlineData(-1200d, 50d, false)]  // 80 px of the right edge is not enough
    [InlineData(-1199d, 50d, true)]
    [InlineData(100d, 1040d, false)]  // title bar below the bottom
    [InlineData(100d, 1039d, true)]
    [InlineData(100d, -11d, false)]   // title bar above the top
    [InlineData(100d, -10d, true)]
    public void APlacementIsOnlyRestoredWhereItsTitleBarCanBeReached(double left, double top, bool restored)
    {
        Assert.Equal(restored, WindowLogic.RestoredBounds(left, top, 1280, 820, Screen, 980, 620) is not null);
    }

    [Fact]
    public void AScreenLeftOfThePrimaryOneCounts()
    {
        var twoScreens = new Rect(-1920, 0, 3840, 1080);

        Assert.NotNull(WindowLogic.RestoredBounds(-1800, 20, 1280, 820, twoScreens, 980, 620));
        Assert.Null(WindowLogic.RestoredBounds(-1800, 20, 1280, 820, Screen, 980, 620));
    }

    [Fact]
    public void AFailureIsReportedWithItsInnerMessageOnlyWhenThatAddsSomething()
    {
        Assert.Equal("Plain.", WindowLogic.FailureText(new InvalidOperationException("Plain.")));
        Assert.Equal("Outer. Inner.", WindowLogic.FailureText(new InvalidOperationException("Outer.", new IOException("Inner."))));
        Assert.Equal("Outer: Inner.", WindowLogic.FailureText(new InvalidOperationException("Outer: Inner.", new IOException("Inner."))));
    }

    [Fact]
    public void AStartupFailureIsRetriedRevokedOrFatal()
    {
        Assert.Equal(ConnectFailure.Retry, WindowLogic.ClassifyConnectFailure(new HttpRequestException("down")));
        Assert.Equal(ConnectFailure.Retry, WindowLogic.ClassifyConnectFailure(new BusApiException(503, "busy", "busy")));
        Assert.Equal(ConnectFailure.Revoked, WindowLogic.ClassifyConnectFailure(new BusApiException(401, "no", "no")));
        Assert.Equal(ConnectFailure.Fatal, WindowLogic.ClassifyConnectFailure(new BusApiException(403, "no", "no")));
        Assert.Equal(ConnectFailure.Fatal, WindowLogic.ClassifyConnectFailure(new InvalidOperationException("bug")));
    }

    [Fact]
    public async Task RepeatWaitsFirstThenRunsEveryIntervalUntilStopped()
    {
        var waits = new List<TimeSpan>();
        var runs = 0;

        await WindowLogic.RepeatAsync(
            time => { waits.Add(time); return Task.CompletedTask; },
            TimeSpan.FromSeconds(8), TimeSpan.FromHours(4),
            () => runs == 3,
            () => { runs++; return Task.CompletedTask; });

        Assert.Equal(3, runs);
        Assert.Equal([TimeSpan.FromSeconds(8), TimeSpan.FromHours(4), TimeSpan.FromHours(4), TimeSpan.FromHours(4)], waits);
    }

    [Fact]
    public async Task RepeatDoesNothingWhenAlreadyStoppedAndEndsQuietlyOnAFailure()
    {
        var runs = 0;
        await WindowLogic.RepeatAsync(_ => Task.CompletedTask, TimeSpan.Zero, TimeSpan.Zero, () => true, () => { runs++; return Task.CompletedTask; });
        Assert.Equal(0, runs);

        await WindowLogic.RepeatAsync(_ => Task.CompletedTask, TimeSpan.Zero, TimeSpan.Zero, () => false,
            () => { runs++; throw new InvalidOperationException("offline"); });
        Assert.Equal(1, runs);
    }
}

public class NavigationLogicTests
{
    [Fact]
    public void SettingsIsShownOnItsOwnWhetherEnrolledOrNot()
    {
        Assert.Equal(new PageLayout(true, false, false, false, false, false), NavigationLogic.Layout(NavPage.Settings, enrolled: true));
        Assert.Equal(new PageLayout(true, false, false, false, false, false), NavigationLogic.Layout(NavPage.Settings, enrolled: false));
    }

    [Fact]
    public void AnEnrolledPcGetsTheWorkspaceWithTheChosenPage()
    {
        Assert.Equal(new PageLayout(false, false, true, true, false, false), NavigationLogic.Layout(NavPage.Monitor, enrolled: true));
        Assert.Equal(new PageLayout(false, false, true, false, true, false), NavigationLogic.Layout(NavPage.Humans, enrolled: true));
        Assert.Equal(new PageLayout(false, false, true, false, false, true), NavigationLogic.Layout(NavPage.Admin, enrolled: true));
    }

    [Fact]
    public void AnUnenrolledPcGetsTheEnrollmentPanelInsteadOfTheWorkspace()
    {
        var layout = NavigationLogic.Layout(NavPage.Monitor, enrolled: false);

        Assert.True(layout.Enrollment);
        Assert.False(layout.Workspace);
    }

    [Theory]
    [InlineData(Key.K, ModifierKeys.Control, true, false, "OpenQuickFind")]
    [InlineData(Key.K, ModifierKeys.Control, true, true, "CloseQuickFind")]
    [InlineData(Key.K, ModifierKeys.Control, false, false, "None")]
    [InlineData(Key.K, ModifierKeys.None, true, false, "None")]
    [InlineData(Key.K, ModifierKeys.Control | ModifierKeys.Shift, true, false, "None")]
    [InlineData(Key.J, ModifierKeys.Control, true, false, "None")]
    [InlineData(Key.Escape, ModifierKeys.None, true, true, "CloseQuickFind")]
    [InlineData(Key.Escape, ModifierKeys.None, true, false, "None")]
    [InlineData(Key.Escape, ModifierKeys.Control, false, true, "CloseQuickFind")]
    public void CtrlKTogglesQuickFindAndEscapeClosesIt(Key key, ModifierKeys modifiers, bool enrolled, bool open, string expected)
    {
        Assert.Equal(expected, NavigationLogic.Shortcut(key, modifiers, enrolled, open).ToString());
    }
}
