using System.Windows;
using System.Windows.Media;

namespace StruggleBusMonitor;

/// <summary>
/// One Omarchy palette. Values come from each theme's colors.toml in basecamp/omarchy:
/// background, foreground and accent directly; Ok/Warn/Bad from color2/color3/color1 unless the
/// theme has no usable hue there (noted inline).
/// </summary>
public sealed record ThemePalette(
    string Id, string Name, bool IsLight,
    string Background, string Foreground, string Accent,
    string Ok, string Warn, string Bad);

public static class Themes
{
    public const string DefaultDark = "retro-82";
    public const string DefaultLight = "catppuccin-latte";

    public static readonly IReadOnlyList<ThemePalette> All =
    [
        new("retro-82", "Retro 82", false, "#05182e", "#f6dcac", "#faa968", "#028391", "#e97b3c", "#f85525"),
        new("tokyo-night", "Tokyo Night", false, "#1a1b26", "#a9b1d6", "#7aa2f7", "#9ece6a", "#e0af68", "#f7768e"),
        new("catppuccin", "Catppuccin", false, "#1e1e2e", "#cdd6f4", "#89b4fa", "#a6e3a1", "#f9e2af", "#f38ba8"),
        new("everforest", "Everforest", false, "#2d353b", "#d3c6aa", "#7fbbb3", "#a7c080", "#dbbc7f", "#e67e80"),
        new("gruvbox", "Gruvbox", false, "#282828", "#d4be98", "#7daea3", "#a9b665", "#d8a657", "#ea6962"),
        new("kanagawa", "Kanagawa", false, "#1f1f28", "#dcd7ba", "#7e9cd8", "#76946a", "#c0a36e", "#c34043"),
        new("nord", "Nord", false, "#2e3440", "#d8dee9", "#81a1c1", "#a3be8c", "#ebcb8b", "#bf616a"),
        // color3 is a second green in this theme, so Warn uses color5.
        new("osaka-jade", "Osaka Jade", false, "#111c18", "#c1c497", "#509475", "#549e6a", "#d2689c", "#ff5345"),
        new("ristretto", "Ristretto", false, "#2c2525", "#e6d9db", "#f38d70", "#adda78", "#f9cc6c", "#fd6883"),
        // No green in this theme: Ok is its yellow (color2) and Warn is the accent orange.
        new("matte-black", "Matte Black", false, "#121212", "#bebebe", "#e68e0d", "#ffc107", "#e68e0d", "#d35f5f"),
        new("ethereal", "Ethereal", false, "#060b1e", "#ffcead", "#7d82d9", "#92a593", "#e9bb4f", "#ed5b5a"),
        // The next four are near-monochrome by design; status is always labelled as well as coloured.
        new("hackerman", "Hackerman", false, "#0b0c16", "#ddf7ff", "#82fb9c", "#4fe88f", "#50f7d4", "#50f872"),
        new("lumon", "Lumon", false, "#16242d", "#d6e2ee", "#8bc9eb", "#5e95bc", "#6fa4c9", "#4d86b0"),
        new("miasma", "Miasma", false, "#222222", "#c2c2b0", "#78824b", "#5f875f", "#b36d43", "#685742"),
        new("vantablack", "Vantablack", false, "#000000", "#ffffff", "#8d8d8d", "#b6b6b6", "#cecece", "#a4a4a4"),
        new("catppuccin-latte", "Catppuccin Latte", true, "#eff1f5", "#4c4f69", "#1e66f5", "#40a02b", "#df8e1d", "#d20f39"),
        new("flexoki-light", "Flexoki Light", true, "#fffcf0", "#100f0f", "#205ea6", "#879a39", "#d0a215", "#d14d41"),
        new("rose-pine", "Rose Pine", true, "#faf4ed", "#575279", "#56949f", "#286983", "#ea9d34", "#b4637a"),
        new("white", "White", true, "#ffffff", "#000000", "#6e6e6e", "#3a3a3a", "#4a4a4a", "#2a2a2a")
    ];

    public static ThemePalette Find(string? id, bool light)
    {
        var match = All.FirstOrDefault(theme => theme.Id == id && theme.IsLight == light);
        return match ?? All.First(theme => theme.Id == (light ? DefaultLight : DefaultDark));
    }

    public static Color Parse(string hex) => (Color)ColorConverter.ConvertFromString(hex);

    /// <summary>Linear sRGB blend: <paramref name="amount"/> of <paramref name="a"/> over <paramref name="b"/>.</summary>
    public static Color Mix(Color a, Color b, double amount)
    {
        byte Channel(byte x, byte y) => (byte)Math.Round(x * amount + y * (1 - amount));
        return Color.FromRgb(Channel(a.R, b.R), Channel(a.G, b.G), Channel(a.B, b.B));
    }

    public static double Contrast(Color a, Color b)
    {
        static double Luminance(Color c)
        {
            static double Linear(byte v)
            {
                var s = v / 255.0;
                return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
            }
            return 0.2126 * Linear(c.R) + 0.7152 * Linear(c.G) + 0.0722 * Linear(c.B);
        }
        var (hi, lo) = (Math.Max(Luminance(a), Luminance(b)), Math.Min(Luminance(a), Luminance(b)));
        return (hi + 0.05) / (lo + 0.05);
    }

    /// <summary>
    /// Every brush the UI uses, derived from the six palette colours. Text colours are pushed toward
    /// the foreground until they reach 4.5:1 on the background, so any palette stays readable.
    /// </summary>
    public static IReadOnlyDictionary<string, Color> Derive(ThemePalette palette)
    {
        var bg = Parse(palette.Background);
        var fg = Parse(palette.Foreground);
        var accent = Parse(palette.Accent);

        Color Readable(Color start, double startMix)
        {
            for (var mix = startMix; mix < 1.0; mix += 0.04)
            {
                var candidate = Mix(fg, start, mix);
                if (Contrast(candidate, bg) >= 4.5) return candidate;
            }
            return fg;
        }

        return new Dictionary<string, Color>
        {
            ["Bg"] = bg,
            ["Fg"] = fg,
            ["Accent"] = accent,
            ["Ok"] = Parse(palette.Ok),
            ["Warn"] = Parse(palette.Warn),
            ["Bad"] = Parse(palette.Bad),
            ["S1"] = Mix(fg, bg, 0.04),
            ["S2"] = Mix(fg, bg, 0.10),
            ["Line"] = Mix(fg, bg, 0.18),
            ["Muted"] = Readable(bg, 0.60),
            ["AccentSoft"] = Mix(accent, bg, 0.18),
            ["AccentText"] = Readable(accent, 0.0),
            ["OnAccent"] = On(accent),
            ["OnBad"] = On(Parse(palette.Bad))
        };

        // Text on a filled colour: the palette's own background or foreground when either reads
        // well, otherwise whichever of black and white reads best (mid-tone accents need this).
        Color On(Color fill)
        {
            var own = Contrast(bg, fill) >= Contrast(fg, fill) ? bg : fg;
            if (Contrast(own, fill) >= 4.5) return own;
            return new[] { own, Colors.Black, Colors.White }.MaxBy(candidate => Contrast(candidate, fill));
        }
    }

    public static void Apply(ResourceDictionary resources, ThemePalette palette)
    {
        foreach (var (key, color) in Derive(palette))
        {
            var brush = new SolidColorBrush(color);
            brush.Freeze();
            resources[key] = brush;
        }
        var scrim = new SolidColorBrush(Parse(palette.Background)) { Opacity = 0.72 };
        scrim.Freeze();
        resources["Scrim"] = scrim;
    }
}
