"""dial_display_palette.py -- every colour and alpha the dial's panel paints with.

One place for the display's colours so the compositor, the display manager
and the hardware backend agree on them. Pure data: no imports, no drawing
library.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

# Overlay dim factor: the top and bottom bands are multiplied down to this
# fraction of their brightness before the glyphs/text are drawn on top, the
# same ImageEnhance.Brightness idiom dial_display_image.py uses for the
# ambient-blur backdrop (see BACKDROP_DARKEN_PERCENT there). 0.32 reads as a
# ~68% dim — dark enough that the glyphs and the pressed-zone highlight are
# unambiguous against any artwork, while the dimmed art is still faintly
# visible behind it. Set against real hardware: 0.4 left bright album art
# competing with the glyphs. The middle half of the panel is never dimmed.
OVERLAY_DIM_FACTOR = 0.32

# Glyph stroke colour and the pressed-zone highlight fill, chosen for
# contrast against the dimmed backdrop produced by OVERLAY_DIM_FACTOR. Text
# (artist name, volume number) is drawn in the same colour — see
# the compositor's _draw_text_safe().
GLYPH_RGB = (255, 255, 255)
PRESSED_FILL_RGB = (255, 255, 255)
PRESSED_FILL_ALPHA = 70  # out of 255 — a translucent highlight wash.

# The current-row wash on the list chassis: the same translucent white
# wash a press uses, at a fraction of the strength, drawn under any press
# so a pressed current row still reads brighter than an unpressed one.
# Alpha 21 lifts the (16,16,16) chassis to (36,36,36): visibly lighter
# than the chassis, still darker than the (48,48,48) separators, and far
# from competing with white text or the marker.
ROW_HIGHLIGHT_RGB = (255, 255, 255)
ROW_HIGHLIGHT_ALPHA = 21

# The mute cell while muted, or while everything playing is paused: a red
# wash that pulses between see-through and solid, so the state cannot be
# missed on a dim, low-contrast panel. The white glyph reads at both ends;
# a press still adds its own white wash on top.
ALERT_RGB = (220, 40, 40)
ALERT_ALPHA_LOW = 72
ALERT_ALPHA_HIGH = 255

# An on/off switch: while on, a white track and a white knob ringed in
# SWITCH_RING_RGB so it stands out from the track; while off, a white
# outline track and a plain white knob.
SWITCH_RING_RGB = (28, 28, 28)

# The compact repeat page's "Repeat Play" row while armed: lit with a white
# wash that still lets the artwork show, under a dark label.
ARMED_ROW_RGB = (255, 255, 255)
ARMED_ROW_ALPHA = 166
ARMED_LABEL_RGB = (16, 16, 16)

# Divider-line colour: pure white, matching the glyph/text colour, so the
# single boundary line between DOWN and UP reads as clean structure against
# the dimmed backdrop rather than blending into it.
DIVIDER_RGB = (255, 255, 255)

HALO_RGBA = (0, 0, 0, 255)

# Selector chassis (compose_list) — a dark background distinct from any
# artwork, so the list unambiguously reads as a different screen.
LIST_BG_RGB = (16, 16, 16)
LIST_SEPARATOR_RGB = (48, 48, 48)

# A disabled repeat-screen label (Start/Stop when the daemon state does not
# accept that action right now) is drawn in this dimmed shade of the glyph
# colour — the same OVERLAY_DIM_FACTOR the overlay's chevrons use for their
# own disabled state.
DIMMED_GLYPH_RGB = tuple(round(c * OVERLAY_DIM_FACTOR) for c in GLYPH_RGB)

# The idle screen's Wi-Fi glyph while the link is down alternates between
# all-grey (DIMMED_GLYPH_RGB) and this alarm red — a clear "something is
# wrong" that still reads against a dimmed logo.
ALARM_RGB = (226, 62, 51)

# The bell's fill by the worst severity it holds: the warning orange, the
# danger red, and the accent blue for an informational entry.
BELL_WARNING_RGB = (233, 113, 50)
BELL_CRITICAL_RGB = (220, 53, 69)
BELL_INFO_RGB = (82, 152, 216)

# The dark translucent disc under the bell on resting artwork.
CORNER_DISC_RGBA = (0, 0, 0, 150)

# A plain dark base pushed for the moment between the display switching to
# show a different appliance and that appliance's own artwork/logo actually
# landing. A step lighter than the list chassis (16, 16, 16) so it reads as
# "waiting", not as a list screen.
TRANSITION_RGB = (32, 32, 32)

# Matches the web UI dark-theme --color-bg and the logo asset's own
# background, so letterbox padding is seamless.
LOGO_BACKGROUND_RGB = (14, 40, 65)
