---
tags:
  - appearance
  - text_cursor
---
# `cursor_smear`

{{since('nightly')}}

When set to `true`, enables a Neovide-style deforming smear effect on the
cursor. As the cursor moves across multiple cells, its four corners animate
independently: leading corners race ahead to the destination while trailing
corners lag behind, stretching the cursor body into a parallelogram that
gives a sense of motion and speed.

The smear activates only on multi-cell jumps (e.g. `gg`/`G`, `Ctrl-f`,
mouse clicks). Single-cell moves such as typing or `hjkl` navigation snap
the cursor instantly so the effect is not distracting during normal editing.

All cursor shapes are supported: block, bar, and underline.

```lua
config.cursor_smear = true
```

The animation duration is controlled by
[cursor_animation_length](cursor_animation_length.md), and the relative lag
between the leading and trailing edges is set by
[cursor_trail_size](cursor_trail_size.md).

An optional gradient mode (tail fades to transparent) is available via
[cursor_smear_gradient](cursor_smear_gradient.md).

See also the particle-based trail effects available through
[cursor_trail_style](cursor_trail_style.md).
