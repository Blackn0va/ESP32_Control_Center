# Baut die (GPL-Drittanbieter-)Firmware-Embeds fuer Marauder Control Center.
# Erzeugt: firmware-embed.js  (ESP32-S3 Komplett-Image, 1-Klick offline)
#          parts-embed.js     (Bootloader je Chip-Familie fuer Universal-Reparatur)
#
# Diese Dateien sind .gitignore't und werden NICHT ins Repo committet.
# Voraussetzung: Python 3 + pip, Internet.
#
# Nutzung:  ./scripts/build-embeds.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$fw   = Join-Path $root "fwparts"
New-Item -ItemType Directory -Force $fw | Out-Null

Write-Host "==> esptool installieren (falls noetig)"
python -m pip install --quiet --disable-pip-version-check esptool | Out-Null

$CORE = "2.0.14"   # Arduino-ESP32 Core (passt zu Marauder esp-idf 4.4.5)
$BL   = "https://raw.githubusercontent.com/espressif/arduino-esp32/$CORE/tools/sdk"

Write-Host "==> boot_app0 + Bootloader-ELFs laden"
Invoke-WebRequest "https://raw.githubusercontent.com/espressif/arduino-esp32/$CORE/tools/partitions/boot_app0.bin" -OutFile "$fw\boot_app0.bin"
$elfs = @{
  "$BL/esp32/bin/bootloader_dio_40m.elf"   = "esp32";
  "$BL/esp32s2/bin/bootloader_dio_80m.elf" = "esp32s2";
  "$BL/esp32s3/bin/bootloader_dio_80m.elf" = "esp32s3";
  "$BL/esp32c3/bin/bootloader_dio_80m.elf" = "esp32c3";
}
$freq = @{ esp32="40m"; esp32s2="80m"; esp32s3="80m"; esp32c3="80m" }
foreach ($u in $elfs.Keys) {
  $chip = $elfs[$u]
  Invoke-WebRequest $u -OutFile "$fw\bl_$chip.elf"
  python -m esptool --chip $chip elf2image --flash_mode dio --flash_freq $freq[$chip] --flash_size 4MB -o "$fw\bl_$chip.bin" "$fw\bl_$chip.elf" | Out-Null
  Write-Host ("    bl_{0}.bin" -f $chip)
}

Write-Host "==> Partitionstabelle generieren"
python "$PSScriptRoot\make_parts.py"

Write-Host "==> Marauder ESP32-S3 App vom neuesten Release laden"
$rel = Invoke-RestMethod "https://api.github.com/repos/justcallmekoko/ESP32Marauder/releases/latest" -Headers @{Accept="application/vnd.github+json"}
$asset = $rel.assets | Where-Object { $_.name -match "multiboardS3" } | Select-Object -First 1
if (-not $asset) { throw "multiboardS3-Asset nicht gefunden im Release $($rel.tag_name)" }
Invoke-WebRequest $asset.browser_download_url -OutFile "$fw\app_s3.bin"
Write-Host ("    {0}" -f $asset.name)

Write-Host "==> ESP32-S3 Komplett-Image mergen (@0x0)"
$merged = "$fw\marauder_s3_full.bin"
python -m esptool --chip esp32s3 merge_bin -o $merged --flash-mode dio --flash-freq 80m --flash-size 16MB `
  0x0 "$fw\bl_esp32s3.bin" 0x8000 "$fw\partitions.bin" 0xe000 "$fw\boot_app0.bin" 0x10000 "$fw\app_s3.bin" | Out-Null

function B64($p){ [Convert]::ToBase64String([IO.File]::ReadAllBytes($p)) }

Write-Host "==> firmware-embed.js schreiben (S3 Komplett-Image)"
$b64 = B64 $merged
$js  = "window.EMBEDDED_FW_B64=`"$b64`";`n" +
       "window.EMBEDDED_FW_NAME=`"marauder_s3_full (BL+Part+App @0x0)`";`n" +
       "window.EMBEDDED_FW_MERGED=true;"
[IO.File]::WriteAllText((Join-Path $root "firmware-embed.js"), $js)

Write-Host "==> parts-embed.js schreiben (Bootloader je Familie)"
$parts = B64 "$fw\partitions.bin"; $boot = B64 "$fw\boot_app0.bin"
$e = B64 "$fw\bl_esp32.bin"; $s2 = B64 "$fw\bl_esp32s2.bin"; $s3 = B64 "$fw\bl_esp32s3.bin"; $c3 = B64 "$fw\bl_esp32c3.bin"
$pjs = "window.FW_PART_TABLE=`"$parts`";`n" +
       "window.FW_BOOTAPP0=`"$boot`";`n" +
       "window.FW_PARTS={`n" +
       " esp32:{bl:`"$e`",blOff:4096},`n" +
       " esp32s2:{bl:`"$s2`",blOff:4096},`n" +
       " esp32s3:{bl:`"$s3`",blOff:0},`n" +
       " esp32c3:{bl:`"$c3`",blOff:0}`n};"
[IO.File]::WriteAllText((Join-Path $root "parts-embed.js"), $pjs)

Write-Host "`n==> Fertig. firmware-embed.js + parts-embed.js erzeugt (nicht committen)."
