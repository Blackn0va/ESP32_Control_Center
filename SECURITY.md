# Security Policy

## Scope

This project is a **local, client-side** web tool. It has no backend, stores no
data off-device (only browser `localStorage`), and communicates only with:

- a USB/serial device you explicitly select (Web Serial), and
- GitHub (to list/download Marauder firmware releases) and a CDN (to load
  `esptool-js`), only when you use the flasher.

## Reporting a vulnerability

If you find a security issue in **this project's code** (e.g. an XSS via parsed
serial output, a supply-chain concern, unsafe handling of downloaded binaries),
please open a **private** advisory via GitHub Security Advisories, or open an issue
without exploit details and ask for a private channel.

Please do **not** report issues that are inherent to the ESP32 Marauder firmware
here — report those upstream at
<https://github.com/justcallmekoko/ESP32Marauder>.

## Not in scope

- Misuse of the tool against unauthorized targets (that is on the user — see
  [DISCLAIMER.md](DISCLAIMER.md)).
- Vulnerabilities in third-party firmware, esptool-js, or the browser.

Thanks for helping keep users safe.
