"""autostream_webui_assets.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Web assets (e.g. CSS) to support the autostream web front-end.
"""

import autostream_webui_static as static

BANNER_LOGO_HTML = """
  <div class="banner-logo-wrap">
    <a href="/" title="autostream Home" aria-label="autostream Home" class="banner-logo-link">
      <img src="/autostream-badge.png" alt="AutoStream" class="banner-logo banner-logo-light">
      <img src="/autostream-badge-dark.png" alt="AutoStream" class="banner-logo banner-logo-dark">
    </a>
  </div>
"""


def logo_banner_html() -> str:
    """The logo banner markup followed by the tag of the script that rolls the
    flash banner up. A function because the tag carries the file's content hash,
    read on first use."""
    return BANNER_LOGO_HTML + static.script_tag("page/banner_dismiss.js")


LICENSE_BANNER_CSS = ""

VIEWPORT_META = '<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">'

# Single-OK-button info modal, shared by every page that needs to surface a
# dismissable notice. Pair with nginx/static/page/info_modal.js, which
# defines the showInfoModal(title, message, isHtml) function driving this markup.
INFO_MODAL_HTML = """
<div id="infoModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="infoModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="infoModalTitle">Notice</div>
    <div class="bd modal-bd modal-bd-scroll">
      <div id="infoModalMessage"></div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-primary" id="infoModalOk">OK</button>
    </div>
  </div>
</div>"""

# Buttonless modal shown by settingsTransact (see nginx/static/page/autosave.js)
# while a restart-required setting's daemon restart is in flight. No footer/buttons —
# it dismisses itself once /api/owntone/ready reports the restart finished.
RESTART_MODAL_HTML = """
<div id="restartModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="restartModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="restartModalTitle">Applying setting&hellip;</div>
    <div class="bd modal-bd">
      <p>OwnTone is restarting to apply the change. Playback will pause briefly.</p>
    </div>
  </div>
</div>"""

A2HS_PROMPT_HTML = """
  <div id="a2hs-prompt" style="display:none;">
    <div id="a2hs-inner">
      <strong>autostream works like an app!</strong>
      <p>
        For easier access, add autostream to your home screen. Hit '...' below, then choose <b>Share</b>,
        then scroll down and chose <b>Add to Home Screen</b>.
      </p>
      <button type="button" id="a2hs-close">Got it</button>
    </div>
  </div>
"""

# ── Bottom nav icons (Feather-style inline SVG) ──────────────────────────────

NAV_ICON_HOME = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"/>'
    '<path d="M9 21V12h6v9"/>'
    '</svg>'
)

NAV_ICON_SETUP = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="3"/>'
    '<path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0'
    'l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09'
    'A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06'
    'A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9'
    'a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68'
    'a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33'
    'l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21'
    'a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>'
    '</svg>'
)

NAV_ICON_LOGS = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<line x1="8" y1="6" x2="21" y2="6"/>'
    '<line x1="8" y1="12" x2="21" y2="12"/>'
    '<line x1="8" y1="18" x2="21" y2="18"/>'
    '<line x1="3" y1="6" x2="3.01" y2="6"/>'
    '<line x1="3" y1="12" x2="3.01" y2="12"/>'
    '<line x1="3" y1="18" x2="3.01" y2="18"/>'
    '</svg>'
)

NAV_ICON_ABOUT = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="10"/>'
    '<line x1="12" y1="16" x2="12" y2="12"/>'
    '<line x1="12" y1="8" x2="12.01" y2="8"/>'
    '</svg>'
)

NAV_ICON_EQUALISER = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<line x1="4" y1="21" x2="4" y2="14"/>'
    '<line x1="4" y1="10" x2="4" y2="3"/>'
    '<line x1="12" y1="21" x2="12" y2="12"/>'
    '<line x1="12" y1="8" x2="12" y2="3"/>'
    '<line x1="20" y1="21" x2="20" y2="16"/>'
    '<line x1="20" y1="12" x2="20" y2="3"/>'
    '<line x1="1" y1="14" x2="7" y2="14"/>'
    '<line x1="9" y1="8" x2="15" y2="8"/>'
    '<line x1="17" y1="16" x2="23" y2="16"/>'
    '</svg>'
)

NAV_ICON_SERVICE = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77'
    'a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91'
    'a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'
    '</svg>'
)

# ── Input type icons (Now Playing card) ──────────────────────────────────────

ICON_TURNTABLE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 206 206"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="2.5"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    # Outer case
    '<rect x="2.5" y="4.5" width="201" height="200" rx="4"/>'
    # Record
    '<circle cx="87" cy="95" r="69"/>'
    '<circle cx="87" cy="95" r="26"/>'
    '<circle cx="87" cy="95" r="3"/>'
    # Record grooves
    '<path d="M31 81 C38 59,56 43,80 38"/>'
    '<path d="M43 87 C52 67,66 55,81 51"/>'
    # Tonearm pivot
    '<circle cx="177" cy="47" r="13"/>'
    '<circle cx="177" cy="47" r="5"/>'
    # Tonearm base block
    '<rect x="169" y="21" width="14" height="14"/>'
    # Tonearm
    '<path d="M177 60 L177 101"/>'
    '<path d="M177 101 C177 111,172 119,165 126"/>'
    '<path d="M165 126 L143 148"/>'
    '<path d="M188 59 L188 102"/>'
    '<path d="M188 102 C188 116,181 129,171 139"/>'
    '<path d="M171 139 L152 158"/>'
    # Cartridge / needle
    '<rect x="141" y="136" width="18" height="27" transform="rotate(45 141 136)"/>'
    '<path d="M156 156 L166 166"/>'
    # Buttons
    '<circle cx="156" cy="178" r="8"/>'
    '<rect x="176" y="170" width="11" height="18" rx="5.5"/>'
    '</svg>'
)

ICON_CD = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 206 206"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="3"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    # Front panel; its bottom edge sits behind the drawer
    '<path d="M32.7 124 H6.5 a4 4 0 0 1 -4 -4 V27.5 a4 4 0 0 1 4 -4 H199.5 a4 4 0 0 1 4 4 V120 a4 4 0 0 1 -4 4 H175.2"/>'
    # Display
    '<rect x="18" y="50" width="92" height="22" rx="3"/>'
    # Buttons
    '<circle cx="153" cy="61" r="10"/>'
    '<circle cx="181" cy="61" r="6"/>'
    # Drawer slot
    '<path d="M36.9 109.4 H31 V89.3 H174.3 V109.4 H171"/>'
    # Drawer sides, widening towards the viewer
    '<path d="M42.7 89.3 L22.6 159.5"/>'
    '<path d="M165.1 89.3 L185.3 159.5"/>'
    # Drawer front and handle
    '<rect x="15.3" y="159.5" width="175.4" height="23" rx="3"/>'
    '<rect x="82" y="168" width="41" height="6.5" rx="3.25"/>'
    # Disc on the drawer, near edge behind the drawer front
    '<path d="M137 159.5 A62.9 36.5 0 1 0 69 159.5"/>'
    '<ellipse cx="103" cy="128.8" rx="21.2" ry="13.2"/>'
    '<ellipse cx="103" cy="128.8" rx="5.1" ry="3.3"/>'
    # Disc sheen
    '<path d="M54.4 121.2 A50.3 29.2 0 0 1 85.8 101.4"/>'
    '<path d="M66.6 123.1 A37.7 21.9 0 0 1 90.1 108.2"/>'
    '</svg>'
)

ICON_LINE_LEVEL = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 258"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="7"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    # Top cable
    '<path d="M56 57 V14"/>'
    '<path d="M56 14 C56 9,60 5,64 5"/>'
    '<path d="M64 5 C69 5,72 9,72 14"/>'
    '<path d="M72 14 V57"/>'
    # Upper connector block
    '<path d="M31 57 H96"/>'
    '<path d="M96 57 C99 57,101 60,101 63"/>'
    '<path d="M101 63 V101"/>'
    '<path d="M31 101 V63"/>'
    '<path d="M31 63 C31 60,34 57,37 57"/>'
    # Main body
    '<path d="M21 101 H107"/>'
    '<path d="M107 101 V167"/>'
    '<path d="M107 167 L86 191"/>'
    '<path d="M86 191 H42"/>'
    '<path d="M42 191 L21 167"/>'
    '<path d="M21 167 V101"/>'
    # Strain relief / lower grip
    '<path d="M42 191 V245"/>'
    '<path d="M42 245 C42 250,46 254,51 254"/>'
    '<path d="M51 254 H77"/>'
    '<path d="M77 254 C82 254,86 250,86 245"/>'
    '<path d="M86 245 V191"/>'
    # Grip grooves
    '<path d="M42 209 H57"/>'
    '<path d="M71 209 H86"/>'
    '<path d="M42 226 H57"/>'
    '<path d="M71 226 H86"/>'
    '<path d="M42 243 H57"/>'
    '<path d="M71 243 H86"/>'
    # Front slots
    '<path d="M59 122 H69"/>'
    '<path d="M59 138 H69"/>'
    '<path d="M59 154 H69"/>'
    '</svg>'
)

ICON_BLUETOOTH = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 258"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="7"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M9 74 L119 184 L64 239 L64 19 L119 74 L9 184"/>'
    '</svg>'
)

# A speaker body/cone with a diagonal slash through it, matching the figure
# the dial's own footer glyph draws (see dial_display_compositor.
# _draw_speaker_glyph(muted=True)) so the two UIs use the same symbol --
# including that glyph's own slash centred on the speaker body rather than
# the icon's box. currentColor so it follows whatever color the caller
# applies rather than carrying its own. The WebUI itself no longer renders
# this icon (a mute is shown in the now-playing header text instead); kept
# for the dial-parity note above and any future caller.
ICON_SPEAKER_MUTED = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"'
    ' fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M3 9v6h4l5 5V4L7 9H3z" fill="currentColor" stroke="none"/>'
    '<path d="M1 5l14 14"/>'
    '</svg>'
)

# ── Dial locked-section padlock icons ─────────────────────────────────────────
# Feather-style 24×24, stroke="var(--color-accent)" so they adapt to dark mode.

ICON_PADLOCK_LOCKED = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="var(--color-accent)" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="3" y="11" width="18" height="11" rx="2"/>'
    '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
    '</svg>'
)

ICON_PADLOCK_UNLOCKED = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="var(--color-accent)" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="3" y="11" width="18" height="11" rx="2"/>'
    '<path d="M7 11V7a5 5 0 0 1 9.9-1"/>'
    '</svg>'
)
