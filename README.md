# 📡 Marauder Control Center

A single-file, browser-based control panel **and** firmware flasher for the
[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) — no install,
no drivers beyond your USB-serial chip, runs entirely client-side via the
**Web Serial API**.

> ⚠️ **For authorized security testing, education and research only.**
> Read [DISCLAIMER.md](DISCLAIMER.md) before use. Deauth, beacon/probe spam,
> Evil Portal and BLE spam are illegal against systems you do not own or are not
> explicitly permitted to test.

---

## ✨ Features

- **Flash & repair any common ESP32** (ESP32, S2, S3, C3) directly from the
  browser via [esptool-js](https://github.com/espressif/esptool-js) — auto-detects
  the chip and picks the correct bootloader offsets.
  - One-click **full repair** (bootloader + partitions + app) for bricked boards.
  - **App update** (@0x10000) for boards that already boot.
  - Auto-download the matching Marauder build for your board from GitHub.
- **Live control UI** organized in tabs: System dashboard, WiFi, Attack, BLE,
  Evil Portal, GPS/Wardrive, Settings, Macros.
- **Parsed live tables** — scan output (APs, stations, BLE devices) is parsed out
  of the serial stream into sortable tables; click a row to select a target.
- **Smart-Scan** — the tool hops through all Wi-Fi channels itself and collects
  beacons, so it finds APs even when firmware channel-hopping is off.
- **Settings mirror** — reads the device's current settings into a live table with
  toggles.
- **Command palette** (`Ctrl/Cmd+K`), command history, macro library.
- **Evil Portal HTML builder** with live preview and `index.html` / `ap.config.txt`
  export (for authorized captive-portal testing).
- **Session persistence** — tables, console log and active tab survive a reload
  (localStorage).
- Clean, theme-consistent dark UI. Everything in one `index.html` (plus optional
  generated firmware embeds).

## 🚀 Quick start

Web Serial requires **Chrome or Edge (desktop)** and a **secure context**
(`https://` or `http://localhost`). Opening the file via `file://` disables the
GitHub firmware download (CORS) — serve it locally instead:

```bash
# Python (any OS)
python -m http.server 8000
# then open http://localhost:8000

# or Node
npx serve .
```

Then:

1. Plug your ESP32 into the **UART** USB port (stable CLI; the native USB port
   re-enumerates when the app boots).
2. Pick a baud rate (Marauder default **115200**) and click **Verbinden / Connect**.
3. Type `help` or use the tabs.

### Flashing

Firmware binaries are **not** shipped in this repo (they are third-party GPL
software — see below). Two ways to get them:

- **Online (recommended):** open the **Flash** tab → *Marauder-Builds laden* →
  pick your board → **App flashen** (update) or **Voll-Reparatur** (full repair).
  The tool downloads the matching build from the official Marauder releases.
- **Offline embeds:** run the build script to bake a board image into the page:

```powershell
# Windows PowerShell, needs Python + pip
./scripts/build-embeds.ps1
```

This downloads the Marauder app + Arduino-ESP32 bootloaders, generates the
partition table, merges a full ESP32-S3 image and writes `firmware-embed.js`
(one-click S3 repair) and `parts-embed.js` (per-family bootloaders for universal
repair). Both files are `.gitignore`d.

## 🧭 Chip compatibility

| Chip | Full repair (embedded parts) | App flash | Bootloader offset |
|------|:---:|:---:|:---:|
| ESP32 (classic) | ✅ | ✅ | `0x1000` |
| ESP32-S2 | ✅ | ✅ | `0x1000` |
| ESP32-S3 | ✅ (also offline 1-click) | ✅ | `0x0` |
| ESP32-C3 | ✅ | ✅ | `0x0` |
| ESP32-C5 / C6 | ⚠️ app flash only | ✅ | `0x0` |
| ESP32-H2 | — (no Wi-Fi) | — | — |

For chips without embedded bootloaders, use
[flasher.marauder.gg](https://flasher.marauder.gg) for a guaranteed full flash.

## 🛠️ Tech

- Pure HTML/CSS/JS, single file, no framework, no build step for the app itself.
- [esptool-js](https://github.com/espressif/esptool-js) loaded on demand from a CDN
  for flashing.
- Web Serial API for the serial console and target control.

## 📄 Kurzfassung (Deutsch)

Browser-Steuerung + Flasher für den ESP32 Marauder. Läuft komplett lokal (Web
Serial, Chrome/Edge). Flasht/repariert ESP32/S2/S3/C3, erkennt den Chip
automatisch, zeigt Scan-Ergebnisse in Live-Tabellen, hat Smart-Scan über alle
Kanäle, Evil-Portal-Builder, Macro-Bibliothek und Session-Speicherung.
**Nur für autorisierte Tests** – siehe [DISCLAIMER.md](DISCLAIMER.md).

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## ⚖️ License

Source code: **MIT** — see [LICENSE](LICENSE).
Third-party ESP32 Marauder firmware and Arduino-ESP32 bootloaders keep their own
licenses and are **not** part of this repository.

## 🙏 Credits

- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) by JustCallMeKoKo
- [esptool-js](https://github.com/espressif/esptool-js) by Espressif
