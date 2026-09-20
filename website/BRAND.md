# VAIS Boundary: mark and usage

The mark draws the mechanism, not a claim. A proposed action arrives, meets a
boundary with thickness, is changed by it, and leaves as one authorised effect.
It is deliberately not a shield or a padlock, because those assert that a system
is secure and the project explicitly declines that claim.

Three states of one line:

| Part | Meaning | Colour role |
|---|---|---|
| Vertical stroke above the boundary | a model-generated proposal, provenance untrusted | `proposal` |
| Diagonal between the two edges | mediated: canonicalised, argument-bound, re-scoped | `mediated` |
| Vertical stroke below the boundary | one authorised, observable effect | `effect` |
| Two horizontal edges | the deterministic reference monitor | `boundary` |
| Faint fill between the edges | the boundary has thickness; it is a region, not a line | `boundary` at 8% |

The colour changes exactly on the boundary edges. Authority is granted at the
boundary and never upstream of it, so nothing above the top edge is ever green.

## Geometry

Authored on a 64 unit grid. Do not redraw it by eye; scale the SVG.

```
band     rect  x=4  y=24  w=56 h=16     boundary colour at 8% opacity
proposal path  M22 4  V24               stroke-width 4
mediated path  M22 24 L42 40            stroke-width 4
effect   path  M42 40 V60               stroke-width 4
edge     path  M4 24 H60                stroke-width 3
edge     path  M4 40 H60                stroke-width 3
```

Paint order matters. The two edges are drawn last so they cover both junctions;
butt caps meeting at an angle otherwise leave a visible sliver at each corner.

## The band is a tint, never a flat fill

Use the boundary colour at 8% opacity (5% on light grounds), or
`fill="currentColor" opacity="0.06"` when the file is inlined in HTML.

Do not substitute an opaque hex sampled from a screenshot. A flat `#102033`
looks correct on `#07111F` and becomes a dark slab on white, on a slide, on a
sticker and on any transparent export. The tint composites correctly everywhere.

## Colour

| Token | Dark grounds | Light grounds |
|---|---|---|
| `proposal` | `#7890A9` | `#94A3B8` |
| `boundary` / `mediated` | `#E7EDF6` | `#0B192C` |
| `effect` | `#22C55E` | `#15803D` |
| band | `boundary` @ 8% | `boundary` @ 5% |
| ground | `#07111F` / `#0B192C` | `#F8FAFC` |
| hairline | `#263B55` | `#CBD5E1` |

Green darkens to `#15803D` on light grounds so it clears 4.5:1 against white.
`#22C55E` does not.

Seven of these values already appear in
`benchmarks/rc/report/rc7-full-evidence/benchmark-table.svg`, so the mark matches
evidence the project has already published.

Status colours `#EF4444` (deny) and `#F59E0B` (require approval) belong to
reports and diagrams. They are never part of the logo.

## Size

| Context | File |
|---|---|
| 24 px and above | `vais-mark.svg`, the 64 grid master |
| Below 24 px | `vais-mark-16.svg`, the pixel-snapped icon master |

The icon master replaces the diagonal with a step and drops the band fill.
Every edge falls on a whole pixel, so nothing is antialiased. A diagonal cannot
survive four pixels of height, and a 6% tint over a 16 px icon is roughly two
pixels of nothing.

Do not scale the 64 grid master down to 16 px, and do not scale the icon master
above 32 px.

## Clear space

Keep clear space equal to the height of the boundary band (16 units at the
mark's own scale) on all four sides. Nothing sits inside it.

Minimum sizes: mark alone 16 px; horizontal lockup 120 px wide; stacked lockup
72 px wide. Below the lockup minimums, use the mark alone.

## Lockups

`vais-logo-horizontal` is the default. The wordmark cap height is 55% of the
mark's box, and `BOUNDARY` is tracked so it measures exactly the same width as
`VAIS` above it. Both are flush left to each other.

Type is Space Grotesk 700 for `VAIS` at -0.035em, and IBM Plex Mono 500 for
`BOUNDARY` at +0.38em. All shipped files carry the type as outlines, so nothing
depends on a font being installed.

## Do not

- Close the aperture, straighten the diagonal, or align the exit under the entry.
  The offset is the idea: what leaves is not what arrived.
- Colour anything above the top edge green.
- Fade the two edges along with the band. As the fill recedes the edges are the
  boundary's only voice; soften them and the mark becomes a line with a kink.
- Place the mark inside a shield, badge or padlock outline.
- Rotate, skew, or add gradients, glows or drop shadows.
- Re-set the wordmark in another face, letterspace `VAIS`, translate it, or
  expand the acronym inside the lockup.

## Files

```
svg/
  vais-mark.svg                     64 grid master, dark grounds
  vais-mark-light.svg               64 grid master, light grounds
  vais-mark-mono.svg                currentColor, for inlining in HTML
  vais-mark-16.svg                  icon master, dark grounds
  vais-mark-16-light.svg            icon master, light grounds
  vais-logo-horizontal.svg          default lockup
  vais-logo-horizontal-light.svg
  vais-logo-stacked.svg
  vais-logo-stacked-light.svg
  vais-wordmark.svg                 type only, no mark
  vais-wordmark-light.svg
  vais-readme-header.svg            1200 x 220
  vais-readme-header-light.svg
  vais-social-preview.svg           1280 x 640
png/
  vais-mark-{512,256,128,64,48}.png       from the 64 grid master
  vais-mark-{32,16}.png                   from the icon master
  vais-mark-light-512.png
  vais-logo-horizontal-1024.png
  vais-logo-horizontal-light-1024.png
  vais-logo-stacked-512.png
  vais-readme-header-1200x220.png
  vais-readme-header-light-1200x220.png
  vais-social-preview-1280x640.png
favicon.ico                         16, 32 and 48 embedded, each from its own master
```

`vais-mark-mono.svg` inherits `color` from its parent element, so it only works
inlined in HTML. Referenced through `<img src>` it has no colour to inherit and
renders black.

## Where they go

- GitHub social preview: Settings, Social preview, upload
  `png/vais-social-preview-1280x640.png`.
- Repository avatar: `png/vais-mark-512.png`.
- Docs site favicon: `favicon.ico`.
- README: see `README-snippet.md`.

## Trademark

Apache 2.0 covers the code, not project marks. If the mark should stay tied to
this project, say so explicitly in `LICENSING.md` rather than leaving it to be
inferred from the code licence.
