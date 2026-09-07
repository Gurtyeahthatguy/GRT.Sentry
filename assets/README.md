# Application icon

`sentry.png` is the source artwork, at the size it was drawn. Every icon the
build needs is generated from it:

    npx tauri icon assets/sentry.png

The generator also writes iOS assets. They are deleted and gitignored, because
signing them requires a verified identity this project does not have.

The corners outside the circle are transparent. A desktop that does not mask
icons itself would otherwise show a coloured square.

To replace the drawing, put a square PNG here and run the command above.
