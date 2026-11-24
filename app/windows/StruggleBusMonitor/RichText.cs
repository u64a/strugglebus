using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;

namespace StruggleBusMonitor;

/// <summary>
/// Renders message text into a TextBlock with @mentions and search hits marked. Colours are
/// resource references, so they follow a theme change without rebuilding the text.
/// </summary>
public static class RichText
{
    public static readonly DependencyProperty TextProperty = DependencyProperty.RegisterAttached(
        "Text", typeof(string), typeof(RichText), new PropertyMetadata(string.Empty, OnChanged));

    public static readonly DependencyProperty HighlightProperty = DependencyProperty.RegisterAttached(
        "Highlight", typeof(string), typeof(RichText), new PropertyMetadata(string.Empty, OnChanged));

    public static string GetText(DependencyObject element) => (string)element.GetValue(TextProperty);
    public static void SetText(DependencyObject element, string value) => element.SetValue(TextProperty, value);
    public static string GetHighlight(DependencyObject element) => (string)element.GetValue(HighlightProperty);
    public static void SetHighlight(DependencyObject element, string value) => element.SetValue(HighlightProperty, value);

    private static void OnChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not TextBlock block) return;
        block.Inlines.Clear();
        block.Inlines.AddRange(FeedLogic.Segment(GetText(block) ?? string.Empty, GetHighlight(block)).Select(ToRun));
    }

    private static Run ToRun(TextSegment segment)
    {
        var run = new Run(segment.Text);
        if (segment.Kind == SegmentKind.Mention) MarkMention(run);
        if (segment.Kind == SegmentKind.Hit) MarkHit(run);
        return run;
    }

    private static void MarkMention(Run run)
    {
        run.FontWeight = FontWeights.SemiBold;
        run.SetResourceReference(TextElement.ForegroundProperty, "AccentText");
    }

    private static void MarkHit(Run run)
    {
        run.SetResourceReference(TextElement.BackgroundProperty, "Accent");
        run.SetResourceReference(TextElement.ForegroundProperty, "OnAccent");
    }
}
