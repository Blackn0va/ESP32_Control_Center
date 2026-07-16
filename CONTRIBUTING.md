# Contributing

Thanks for your interest! This is a small single-file project — contributions are
welcome.

## Ground rules

- **Ethical use only.** Do not submit features whose *primary* purpose is to make
  unauthorized attacks easier, to evade detection for malicious ends, or to target
  specific individuals. Parsing, UX, flashing, safety and documentation
  improvements are always welcome.
- Keep the app a **single `index.html`** with no build step where possible.
- Match the existing code style (compact vanilla JS, German UI strings + English
  code identifiers).
- Never commit firmware binaries or the generated `firmware-embed.js` /
  `parts-embed.js` (they are third-party GPL software and are `.gitignore`d).

## Dev setup

```bash
python -m http.server 8000   # or: npx serve .
# open http://localhost:8000 in Chrome/Edge
```

Test against real hardware (any ESP32 running Marauder) or at least verify the
serial parsing with pasted sample output.

## Before opening a PR

- Confirm the page loads without console errors.
- Run a JS syntax check on the module script, e.g.
  `node --check` on the extracted `<script type="module">` block.
- Describe what you changed and how you tested it.

## Reporting bugs

Open an issue with: browser + version, ESP32 chip + Marauder firmware version,
what you did, what you expected, and the relevant **console output** (redact MACs
if you like).
