package com.strugglebus.app.ui.theme

import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt

/**
 * One Omarchy palette, the same table the Windows app uses. Values come from each theme's
 * colors.toml in basecamp/omarchy: background, foreground and accent directly; ok/warn/bad from
 * color2/color3/color1 unless the theme has no usable hue there (noted inline).
 */
data class ThemePalette(
    val id: String,
    val name: String,
    val isLight: Boolean,
    val background: Int,
    val foreground: Int,
    val accent: Int,
    val ok: Int,
    val warn: Int,
    val bad: Int,
)

/** Every colour the UI uses, as 0xRRGGBB, derived from the six palette colours. */
data class DerivedColors(
    val bg: Int,
    val fg: Int,
    val accent: Int,
    val ok: Int,
    val warn: Int,
    val bad: Int,
    val surface1: Int,
    val surface2: Int,
    val line: Int,
    val muted: Int,
    val soft: Int,
    val accentSoft: Int,
    val accentText: Int,
    val okText: Int,
    val badText: Int,
    val onAccent: Int,
    val onBad: Int,
)

object Themes {
    const val DEFAULT_DARK = "retro-82"
    const val DEFAULT_LIGHT = "catppuccin-latte"

    val all: List<ThemePalette> = listOf(
        ThemePalette("retro-82", "Retro 82", false, 0x05182e, 0xf6dcac, 0xfaa968, 0x028391, 0xe97b3c, 0xf85525),
        ThemePalette("tokyo-night", "Tokyo Night", false, 0x1a1b26, 0xa9b1d6, 0x7aa2f7, 0x9ece6a, 0xe0af68, 0xf7768e),
        ThemePalette("catppuccin", "Catppuccin", false, 0x1e1e2e, 0xcdd6f4, 0x89b4fa, 0xa6e3a1, 0xf9e2af, 0xf38ba8),
        ThemePalette("everforest", "Everforest", false, 0x2d353b, 0xd3c6aa, 0x7fbbb3, 0xa7c080, 0xdbbc7f, 0xe67e80),
        ThemePalette("gruvbox", "Gruvbox", false, 0x282828, 0xd4be98, 0x7daea3, 0xa9b665, 0xd8a657, 0xea6962),
        ThemePalette("kanagawa", "Kanagawa", false, 0x1f1f28, 0xdcd7ba, 0x7e9cd8, 0x76946a, 0xc0a36e, 0xc34043),
        ThemePalette("nord", "Nord", false, 0x2e3440, 0xd8dee9, 0x81a1c1, 0xa3be8c, 0xebcb8b, 0xbf616a),
        // color3 is a second green in this theme, so warn uses color5.
        ThemePalette("osaka-jade", "Osaka Jade", false, 0x111c18, 0xc1c497, 0x509475, 0x549e6a, 0xd2689c, 0xff5345),
        ThemePalette("ristretto", "Ristretto", false, 0x2c2525, 0xe6d9db, 0xf38d70, 0xadda78, 0xf9cc6c, 0xfd6883),
        // No green in this theme: ok is its yellow (color2) and warn is the accent orange.
        ThemePalette("matte-black", "Matte Black", false, 0x121212, 0xbebebe, 0xe68e0d, 0xffc107, 0xe68e0d, 0xd35f5f),
        ThemePalette("ethereal", "Ethereal", false, 0x060b1e, 0xffcead, 0x7d82d9, 0x92a593, 0xe9bb4f, 0xed5b5a),
        // The next four are near-monochrome by design; status is always labelled as well as coloured.
        ThemePalette("hackerman", "Hackerman", false, 0x0b0c16, 0xddf7ff, 0x82fb9c, 0x4fe88f, 0x50f7d4, 0x50f872),
        ThemePalette("lumon", "Lumon", false, 0x16242d, 0xd6e2ee, 0x8bc9eb, 0x5e95bc, 0x6fa4c9, 0x4d86b0),
        ThemePalette("miasma", "Miasma", false, 0x222222, 0xc2c2b0, 0x78824b, 0x5f875f, 0xb36d43, 0x685742),
        ThemePalette("vantablack", "Vantablack", false, 0x000000, 0xffffff, 0x8d8d8d, 0xb6b6b6, 0xcecece, 0xa4a4a4),
        ThemePalette("catppuccin-latte", "Catppuccin Latte", true, 0xeff1f5, 0x4c4f69, 0x1e66f5, 0x40a02b, 0xdf8e1d, 0xd20f39),
        ThemePalette("flexoki-light", "Flexoki Light", true, 0xfffcf0, 0x100f0f, 0x205ea6, 0x879a39, 0xd0a215, 0xd14d41),
        ThemePalette("rose-pine", "Rose Pine", true, 0xfaf4ed, 0x575279, 0x56949f, 0x286983, 0xea9d34, 0xb4637a),
        ThemePalette("white", "White", true, 0xffffff, 0x000000, 0x6e6e6e, 0x3a3a3a, 0x4a4a4a, 0x2a2a2a),
    )

    fun find(id: String?, light: Boolean): ThemePalette =
        all.firstOrNull { it.id == id && it.isLight == light }
            ?: all.first { it.id == if (light) DEFAULT_LIGHT else DEFAULT_DARK }

    /** sRGB blend: [amount] of [a] over [b]. */
    fun mix(a: Int, b: Int, amount: Double): Int {
        fun channel(shift: Int): Int {
            val x = (a shr shift) and 0xff
            val y = (b shr shift) and 0xff
            return (x * amount + y * (1 - amount)).roundToInt().coerceIn(0, 255)
        }
        return (channel(16) shl 16) or (channel(8) shl 8) or channel(0)
    }

    fun contrast(a: Int, b: Int): Double {
        fun luminance(c: Int): Double {
            fun linear(v: Int): Double {
                val s = v / 255.0
                return if (s <= 0.03928) s / 12.92 else ((s + 0.055) / 1.055).pow(2.4)
            }
            return 0.2126 * linear((c shr 16) and 0xff) +
                0.7152 * linear((c shr 8) and 0xff) +
                0.0722 * linear(c and 0xff)
        }
        val hi = max(luminance(a), luminance(b))
        val lo = min(luminance(a), luminance(b))
        return (hi + 0.05) / (lo + 0.05)
    }

    /**
     * Text colours are pushed toward the foreground until they reach 4.5:1 on the background, so
     * any palette stays readable.
     */
    fun derive(palette: ThemePalette): DerivedColors {
        val bg = palette.background
        val fg = palette.foreground

        fun readable(start: Int, startMix: Double): Int {
            var amount = startMix
            while (amount < 1.0) {
                val candidate = mix(fg, start, amount)
                if (contrast(candidate, bg) >= 4.5) return candidate
                amount += 0.04
            }
            return fg
        }

        // Text on a filled colour: the palette's own background or foreground when either reads
        // well, otherwise whichever of black and white reads best (mid-tone accents need this).
        fun on(fill: Int): Int {
            val own = if (contrast(bg, fill) >= contrast(fg, fill)) bg else fg
            if (contrast(own, fill) >= 4.5) return own
            return listOf(own, 0x000000, 0xffffff).maxBy { contrast(it, fill) }
        }

        return DerivedColors(
            bg = bg,
            fg = fg,
            accent = palette.accent,
            ok = palette.ok,
            warn = palette.warn,
            bad = palette.bad,
            surface1 = mix(fg, bg, 0.04),
            surface2 = mix(fg, bg, 0.10),
            line = mix(fg, bg, 0.18),
            muted = readable(bg, 0.60),
            soft = readable(bg, 0.78),
            accentSoft = mix(palette.accent, bg, 0.18),
            accentText = readable(palette.accent, 0.0),
            okText = readable(palette.ok, 0.0),
            badText = readable(palette.bad, 0.0),
            onAccent = on(palette.accent),
            onBad = on(palette.bad),
        )
    }
}
