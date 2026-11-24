using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace StruggleBusMonitor;

/// <summary>
/// A TextBlock whose text can be selected with the mouse and copied with Ctrl+C, while keeping the
/// coloured runs a TextBox cannot show. WPF has no public way to do this, so it attaches the
/// framework's own read-only text editor by reflection. If a future runtime moves those internals
/// the control falls back to an ordinary, unselectable TextBlock instead of failing.
/// </summary>
public sealed class SelectableTextBlock : TextBlock
{
    private const BindingFlags Hidden = BindingFlags.Instance | BindingFlags.NonPublic;
    private static readonly Type? EditorType = typeof(FrameworkElement).Assembly.GetType("System.Windows.Documents.TextEditor");
    private static readonly PropertyInfo? ContainerProperty = typeof(TextBlock).GetProperty("TextContainer", Hidden);
    private static readonly bool Registered = Register(EditorType, ContainerProperty);
#pragma warning disable IDE0052 // Held so the editor lives as long as the text it serves.
    private readonly object? _editor;
#pragma warning restore IDE0052

    public static bool IsSupported => Registered;

    public SelectableTextBlock() : this(Registered ? EditorType : null, ContainerProperty)
    {
    }

    /// <summary>
    /// For tests: attaches an editor of <paramref name="editorType"/> to the text read through
    /// <paramref name="containerProperty"/>. Null, or a type that is not WPF's editor, leaves plain text.
    /// </summary>
    internal SelectableTextBlock(Type? editorType, PropertyInfo? containerProperty)
    {
        _editor = editorType is null ? null : TryAttachEditor(editorType, containerProperty);
        if (_editor is null) return;
        Focusable = true;
        FocusVisualStyle = null;
        Cursor = Cursors.IBeam;
    }

    internal bool HasEditor => _editor is not null;

    private object? TryAttachEditor(Type editorType, PropertyInfo? containerProperty)
    {
        try
        {
            var container = containerProperty!.GetValue(this)!;
            var editor = Activator.CreateInstance(editorType, Hidden | BindingFlags.Public | BindingFlags.CreateInstance, null, [container, this, false], null)!;
            editorType.GetProperty("IsReadOnly", Hidden)!.SetValue(editor, true);
            editorType.GetProperty("TextView", Hidden)!.SetValue(editor, container.GetType().GetProperty("TextView", Hidden | BindingFlags.Public)!.GetValue(container));
            return editor;
        }
        catch (Exception error) when (error is TargetInvocationException or MissingMethodException or NullReferenceException or ArgumentException)
        {
            // Plain text is better than no message.
            return null;
        }
    }

    /// <summary>Teaches WPF's editor commands (select, copy) about this control. False when the internals are not there.</summary>
    internal static bool Register(Type? editorType, PropertyInfo? containerProperty)
    {
        try
        {
            if (editorType is null || containerProperty is null) return false;
            var register = editorType.GetMethod("RegisterCommandHandlers", BindingFlags.Static | BindingFlags.NonPublic, null,
                [typeof(Type), typeof(bool), typeof(bool), typeof(bool)], null);
            if (register is null) return false;
            register.Invoke(null, [typeof(SelectableTextBlock), true, true, true]);
            return true;
        }
        catch (Exception error) when (error is TargetInvocationException or AmbiguousMatchException or ArgumentException)
        {
            return false;
        }
    }
}
