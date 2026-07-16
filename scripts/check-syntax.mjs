// Extrahiert den <script type="module"> Block aus index.html und prueft die JS-Syntax.
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const m = html.match(/<script type="module">([\s\S]*?)<\/script>/);
if (!m) { console.error("Kein <script type=module> gefunden"); process.exit(1); }

const tmp = join(mkdtempSync(join(tmpdir(), "mcc-")), "app.mjs");
writeFileSync(tmp, m[1]);
try {
  execFileSync(process.execPath, ["--check", tmp], { stdio: "inherit" });
  console.log("SYNTAX OK");
} catch {
  process.exit(1);
}
