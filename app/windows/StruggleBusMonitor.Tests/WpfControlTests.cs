using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace StruggleBusMonitor.Tests;

public sealed class RichTextTests
{
    [Fact]
    public void Text_BecomesRunsWithMentionsEmphasised() => Sta.Run(() =>
    {
        var block = new TextBlock();

        RichText.SetText(block, "ask @agent-one now");

        var runs = block.Inlines.Cast<Run>().ToList();
        Assert.Equal(["ask ", "@agent-one", " now"], runs.Select(run => run.Text));
        Assert.Equal("ask @agent-one now", RichText.GetText(block));
        Assert.Equal(FontWeights.SemiBold, runs[1].FontWeight);
        Assert.NotEqual(FontWeights.SemiBold, runs[0].FontWeight);
        Assert.NotEqual(DependencyProperty.UnsetValue, runs[1].ReadLocalValue(TextElement.ForegroundProperty));
        Assert.Equal(DependencyProperty.UnsetValue, runs[0].ReadLocalValue(TextElement.ForegroundProperty));
        Assert.Equal(DependencyProperty.UnsetValue, runs[1].ReadLocalValue(TextElement.BackgroundProperty));
    });

    [Fact]
    public void Highlight_MarksSearchHitsWithTheThemeAccent() => Sta.Run(() =>
    {
        var accent = new SolidColorBrush(Colors.Orange);
        var onAccent = new SolidColorBrush(Colors.Black);
        var block = new TextBlock();
        block.Resources["Accent"] = accent;
        block.Resources["OnAccent"] = onAccent;

        RichText.SetText(block, "the disk is full, Disk again");
        RichText.SetHighlight(block, "disk");

        var runs = block.Inlines.Cast<Run>().ToList();
        Assert.Equal(["the ", "disk", " is full, ", "Disk", " again"], runs.Select(run => run.Text));
        Assert.Equal("disk", RichText.GetHighlight(block));
        Assert.Same(accent, runs[1].Background);
        Assert.Same(onAccent, runs[1].Foreground);
        Assert.Same(accent, runs[3].Background);
        Assert.Null(runs[0].Background);
    });

    [Fact]
    public void ChangingTheTextReplacesTheOldRuns() => Sta.Run(() =>
    {
        var block = new TextBlock();
        RichText.SetText(block, "first @agent-one");

        RichText.SetText(block, "second");
        Assert.Equal("second", Assert.Single(block.Inlines.Cast<Run>()).Text);

        RichText.SetText(block, string.Empty);
        Assert.Empty(block.Inlines);
    });

    [Fact]
    public void OtherElementsAreLeftAlone() => Sta.Run(() =>
    {
        var border = new Border();

        RichText.SetText(border, "text");
        RichText.SetHighlight(border, "t");

        Assert.Equal("text", RichText.GetText(border));
        Assert.Null(border.Child);
    });
}

public sealed class SelectableTextBlockTests
{
    private static readonly PropertyInfo? Container =
        typeof(TextBlock).GetProperty("TextContainer", BindingFlags.Instance | BindingFlags.NonPublic);

    /// <summary>Has the handler-registration method WPF's editor has, so the call can be observed.</summary>
    private static class FakeEditor
    {
        public static Type? RegisteredFor { get; private set; }

        private static void RegisterCommandHandlers(Type controlType, bool acceptsRichContent, bool readOnly, bool registerEventListeners) =>
            RegisteredFor = (acceptsRichContent, readOnly, registerEventListeners) == (true, true, true) ? controlType : null;
    }

    private static class BrokenEditor
    {
        private static void RegisterCommandHandlers(Type controlType, bool acceptsRichContent, bool readOnly, bool registerEventListeners) =>
            throw new InvalidOperationException("The editor internals changed.");
    }

    [Fact]
    public void OnThisRuntimeTheTextIsSelectable() => Sta.Run(() =>
    {
        Assert.True(SelectableTextBlock.IsSupported);

        var block = new SelectableTextBlock { Text = "copy me" };

        Assert.True(block.HasEditor);
        Assert.True(block.Focusable);
        Assert.Null(block.FocusVisualStyle);
        Assert.Same(Cursors.IBeam, block.Cursor);
        Assert.Equal("copy me", block.Text);
    });

    [Fact]
    public void WithoutTheEditorItIsAnOrdinaryTextBlock() => Sta.Run(() =>
    {
        var block = new SelectableTextBlock(null, Container) { Text = "still readable" };

        Assert.False(block.HasEditor);
        Assert.False(block.Focusable);
        Assert.Null(block.Cursor);
        Assert.Equal("still readable", block.Text);
    });

    [Fact]
    public void AnEditorThatCannotBeAttachedLeavesPlainText() => Sta.Run(() =>
    {
        var wrongType = new SelectableTextBlock(typeof(Uri), Container) { Text = "still readable" };
        var noContainer = new SelectableTextBlock(typeof(Uri), null);

        Assert.False(wrongType.HasEditor);
        Assert.False(wrongType.Focusable);
        Assert.Equal("still readable", wrongType.Text);
        Assert.False(noContainer.HasEditor);
    });

    [Fact]
    public void Register_HandsTheControlTypeToTheEditor()
    {
        Assert.True(SelectableTextBlock.Register(typeof(FakeEditor), Container));
        Assert.Equal(typeof(SelectableTextBlock), FakeEditor.RegisteredFor);
    }

    [Fact]
    public void Register_ReportsMissingOrBrokenInternalsInsteadOfFailing()
    {
        Assert.NotNull(Container);
        Assert.False(SelectableTextBlock.Register(null, Container));
        Assert.False(SelectableTextBlock.Register(typeof(FakeEditor), null));
        Assert.False(SelectableTextBlock.Register(typeof(Uri), Container));
        Assert.False(SelectableTextBlock.Register(typeof(BrokenEditor), Container));
    }
}

public sealed class ThemeApplyTests
{
    [Fact]
    public void Apply_PutsAFrozenBrushForEveryDerivedColourIntoTheResources()
    {
        var palette = Themes.Find("gruvbox", light: false);
        var resources = new ResourceDictionary { ["Bg"] = Brushes.Magenta };

        Themes.Apply(resources, palette);

        foreach (var (key, color) in Themes.Derive(palette))
        {
            var brush = Assert.IsType<SolidColorBrush>(resources[key]);
            Assert.Equal(color, brush.Color);
            Assert.True(brush.IsFrozen);
        }
        var scrim = Assert.IsType<SolidColorBrush>(resources["Scrim"]);
        Assert.Equal(Themes.Parse(palette.Background), scrim.Color);
        Assert.Equal(0.72, scrim.Opacity);
        Assert.True(scrim.IsFrozen);
    }

    [Fact]
    public void Derive_FallsBackToTheForegroundWhenNoBlendIsReadable()
    {
        var murky = new ThemePalette("murky", "Murky", false, "#808080", "#8a8a8a", "#858585", "#808080", "#808080", "#808080");

        var colors = Themes.Derive(murky);

        Assert.Equal(Themes.Parse("#8a8a8a"), colors["Muted"]);
        Assert.Equal(Themes.Parse("#8a8a8a"), colors["AccentText"]);
        Assert.Contains(colors["OnAccent"], new[] { Colors.Black, Colors.White });
    }
}
