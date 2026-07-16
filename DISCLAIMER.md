# Legal Disclaimer / Rechtlicher Hinweis

## English

**This project is provided strictly for authorized security testing, education,
and research.**

Marauder Control Center is a browser front-end that talks to an ESP32 running the
third-party [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)
firmware over a serial (COM/USB) connection, and can flash that firmware.

Some functions of the underlying firmware (Wi‑Fi deauthentication, beacon/probe
flooding, Evil Portal captive pages, BLE advertisement spam) actively transmit
radio frames that interfere with other devices. Using them against networks,
devices, or persons **without explicit, prior, written authorization is illegal**
in most jurisdictions and can cause real harm.

By using this software you agree that you will:

- Only operate it against hardware, networks and radio spectrum that **you own**
  or for which you hold **explicit written permission** to test.
- Comply with all applicable local, national and international laws and
  radio-frequency regulations.
- Never use it to disrupt, intercept, deceive, or gain unauthorized access to
  systems or communications you are not authorized to test.

The authors and contributors provide this software **"as is", without warranty of
any kind**, and accept **no liability** for any misuse, damage, data loss, legal
consequences, or bricked hardware. **You are solely responsible for your actions.**

If you do not agree, **do not use this software.**

## Deutsch

**Dieses Projekt dient ausschließlich autorisierten Sicherheitstests, Bildung und
Forschung.**

Marauder Control Center ist ein Browser-Frontend, das über eine serielle
(COM/USB-)Verbindung mit einem ESP32 spricht, auf dem die Drittanbieter-Firmware
[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) läuft, und das
diese Firmware flashen kann.

Einige Funktionen der Firmware (WLAN-Deauth, Beacon-/Probe-Flooding, Evil Portal,
BLE-Spam) senden aktiv Funkframes, die andere Geräte stören. Der Einsatz gegen
fremde Netze, Geräte oder Personen **ohne ausdrückliche, vorherige, schriftliche
Genehmigung ist strafbar** – in Deutschland u. a. nach **§ 202a/b/c StGB**
(Ausspähen/Abfangen von Daten, Vorbereiten), **§ 303a/b StGB** (Datenveränderung/
Computersabotage) sowie nach dem **TKG** (Störung von Funkanlagen).

Mit der Nutzung erklärst du dich einverstanden:

- Nur eigene Hardware/Netze zu testen oder solche mit **ausdrücklicher
  schriftlicher Erlaubnis**.
- Alle geltenden Gesetze und Funkvorschriften einzuhalten.
- Nichts zu stören, abzufangen, zu täuschen oder unbefugt darauf zuzugreifen,
  wofür keine Testfreigabe vorliegt.

Die Software wird **ohne jede Gewähr** bereitgestellt. Die Autoren übernehmen
**keine Haftung** für Missbrauch, Schäden, Datenverlust, rechtliche Folgen oder
defekte Hardware (Bricking). **Du allein bist verantwortlich.**

Wenn du nicht einverstanden bist: **nutze diese Software nicht.**
