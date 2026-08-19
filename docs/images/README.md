# The images in the README

All three are screenshots of the tool's own pages, taken from the pages rather than drawn, so
they cannot show a layout the code does not produce. They go stale when the pages change, which
is the cost of that; regenerating them is the fix.

- `landing.png` — `view.page("", Analysis(), Filters())`, the whole `<main>`
- `screenshot.png` — the same page on `examples/two-site`, scrolled to the filter bar
- `timeline.png` — the first `.figure` on that page containing a `svg.viz`

To regenerate: render those three to HTML files, open each in a headless browser at
`device_scale_factor=2`, wait for the entrance animations to finish, and screenshot the element
named above. The wait is not optional — every card enters from `opacity: 0`, and where the
browser drives that from scroll position rather than from time, a card that is off screen when
the shot is taken is a card-shaped hole in the image.

This is deliberately not part of the test suite. It needs a browser, the suite needs nothing but
the standard library, and an image is not a thing a test can judge.
