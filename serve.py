#!/usr/bin/env python3
"""Lokaler Server fuer das Marauder Control Center.

Serviert index.html UND proxyt Firmware-Downloads von GitHub serverseitig.
Damit umgeht der Flash-Tab das CORS-/403-Problem der oeffentlichen Proxies:
der Browser holt die .bin von /proxy?url=..., dieser Server laedt sie und
reicht sie mit Access-Control-Allow-Origin durch.

Start:
    python serve.py            # http://localhost:8000
    python serve.py 9000       # anderer Port

Nur Python-3-Standardbibliothek, keine Abhaengigkeiten.
"""
import http.server
import socketserver
import urllib.request
import urllib.parse
import sys
import os
import re
import json
import base64
import struct
import hmac
import hashlib

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

# Nur diese Host-Suffixe darf der Proxy laden (kein offener SSRF-Proxy).
ALLOWED_SUFFIXES = ("github.com", "githubusercontent.com")


def host_allowed(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in ALLOWED_SUFFIXES)


# ===================== WPA/WPA2-PSK Cracker (reines Python) =====================
# Knackt PMKID (sniffpmkid) und 4-Way-Handshake (sniffdeauth) per Woerterbuch.
# Nur fuer eigene / autorisierte Netze.

def _strip_radiotap(frame, linktype):
    if linktype == 127 and len(frame) >= 4:      # DLT_IEEE802_11_RADIO -> Radiotap-Header abschneiden
        rtlen = int.from_bytes(frame[2:4], "little")
        if 0 < rtlen <= len(frame):
            return frame[rtlen:]
    if linktype == 119 and len(frame) >= 4:      # DLT_PRISM_HEADER (144 Byte fix)
        return frame[144:]
    return frame                                 # 105 = reines 802.11


def parse_pcapng(data):
    """pcapng -> 802.11-Frames. Deckt SHB/IDB/EPB/SPB ab."""
    n = len(data)
    if n < 12:
        return []
    en = ">" if data[8:12] == b"\x1a\x2b\x3c\x4d" else "<"   # BOM roh 1A2B3C4D = big-endian

    def u32(b):
        return int.from_bytes(b, "big" if en == ">" else "little")

    def u16(b):
        return int.from_bytes(b, "big" if en == ">" else "little")
    frames, off, linktype = [], 0, 105
    while off + 12 <= n:
        btype = u32(data[off:off + 4])
        blen = u32(data[off + 4:off + 8])
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1 and len(body) >= 2:                 # IDB
            linktype = u16(body[0:2])
        elif btype == 6 and len(body) >= 20:              # EPB: intf(4)+ts_hi(4)+ts_lo(4)+caplen(4)+origlen(4)+data
            caplen = u32(body[12:16])
            frames.append(_strip_radiotap(body[20:20 + caplen], linktype))
        elif btype == 3 and len(body) >= 4:               # SPB
            origlen = u32(body[0:4])
            frames.append(_strip_radiotap(body[4:4 + origlen], linktype))
        off += blen
    return frames


def parse_pcap(data):
    """pcap ODER pcapng -> Liste von 802.11-Frames (Radiotap entfernt)."""
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":              # pcapng
        return parse_pcapng(data)
    if magic == b"\xd4\xc3\xb2\xa1":
        en = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        en = ">"
    else:
        return []
    linktype = struct.unpack(en + "I", data[20:24])[0]
    out = []
    off, n = 24, len(data)
    while off + 16 <= n:
        _, _, incl, _ = struct.unpack(en + "IIII", data[off:off + 16])
        off += 16
        if incl < 0 or off + incl > n:
            break
        out.append(_strip_radiotap(data[off:off + incl], linktype))
        off += incl
    return out


def pcap_debug(data):
    """Diagnose: Magic, Linktype, Frame-/EAPOL-/Beacon-Zahl."""
    d = {"bytes": len(data), "magic": data[:4].hex() if len(data) >= 4 else ""}
    frames = parse_pcap(data)
    d["frames"] = len(frames)
    eapol = beacon = 0
    for f in frames:
        if len(f) < 24:
            continue
        ft = (f[0] >> 2) & 3
        st = (f[0] >> 4) & 0xF
        if ft == 0 and st in (5, 8):
            beacon += 1
        elif ft == 2 and b"\x88\x8e" in f[24:40]:
            eapol += 1
    d["beacons"] = beacon
    d["eapol"] = eapol
    return d


def _tags(body):
    """802.11-Management Tagged Parameters -> dict{tag_id: value}."""
    tags, i = {}, 0
    while i + 2 <= len(body):
        t, ln = body[i], body[i + 1]
        if i + 2 + ln > len(body):
            break
        tags.setdefault(t, body[i + 2:i + 2 + ln])
        i += 2 + ln
    return tags


def extract_wpa(frames):
    """Sammelt SSID, AP/STA-MACs, PMKID und 4-Way-Felder aus den Frames."""
    info = {"ssid": None, "ap": None, "sta": None, "pmkid": None,
            "anonce": None, "snonce": None, "mic": None, "eapol2": None, "kver": None}
    for f in frames:
        if len(f) < 24:
            continue
        fc = f[0]
        ftype = (fc >> 2) & 3
        subtype = (fc >> 4) & 0xF
        # --- Management: SSID aus Beacon(8)/ProbeResp(5) ---
        if ftype == 0 and subtype in (8, 5):
            body = f[24 + 12:]           # 24 Header + 12 fixed (timestamp/interval/caps)
            ssid = _tags(body).get(0)
            if ssid and info["ssid"] is None and 0 < len(ssid) <= 32 and all(32 <= c < 127 for c in ssid):
                info["ssid"] = ssid
            continue
        # --- Data: EAPOL suchen ---
        if ftype != 2:
            continue
        to_ds, from_ds = f[1] & 1, (f[1] >> 1) & 1
        # Robust: LLC/SNAP+EAPOL-Marker direkt suchen (unabhaengig von QoS/HT/Header-Laenge)
        j = f.find(b"\xaa\xaa\x03\x00\x00\x00\x88\x8e")
        if j < 0:
            continue
        eapol = f[j + 8:]
        if len(eapol) < 99 or eapol[1] != 3:   # EAPOL type 3 = Key
            continue
        # BSSID/STA aus Adressen
        a1, a2, a3 = f[4:10], f[10:16], f[16:22]
        if to_ds and not from_ds:              # STA -> AP
            ap, sta = a1, a2
        elif from_ds and not to_ds:            # AP -> STA
            ap, sta = a2, a1
        else:
            ap, sta = a3, a2
        info["ap"], info["sta"] = info["ap"] or ap, info["sta"] or sta
        key_info = struct.unpack(">H", eapol[5:7])[0]
        nonce = eapol[17:49]
        mic = eapol[81:97]
        kdl = struct.unpack(">H", eapol[97:99])[0]
        kdata = eapol[99:99 + kdl]
        mic_set = bool(key_info & 0x100)
        ack = bool(key_info & 0x080)
        if ack and not mic_set:                # M1: ANonce + evtl. PMKID
            info["anonce"] = info["anonce"] or nonce
            j = kdata.find(b"\x00\x0f\xac\x04")   # PMKID-KDE (OUI 00-0F-AC, Typ 4)
            if j >= 0 and len(kdata) >= j + 4 + 16:
                pm = kdata[j + 4:j + 4 + 16]
                if pm != b"\x00" * 16:
                    info["pmkid"] = pm
        elif mic_set and not ack:              # M2: SNonce + MIC + Frame
            if info["snonce"] is None:
                info["snonce"] = nonce
                info["mic"] = mic
                info["kver"] = key_info & 0x07
                z = bytearray(eapol)
                z[81:97] = b"\x00" * 16        # MIC-Feld fuer Berechnung nullen
                info["eapol2"] = bytes(z)
    return info


def _prf512(pmk, a, b):
    r = b""
    i = 0
    while len(r) < 64:
        r += hmac.new(pmk, a + b"\x00" + b + bytes([i]), hashlib.sha1).digest()
        i += 1
    return r[:64]


def crack(info, words, limit=5000000, progress=None):
    """Woerterbuch-Angriff (CPU). Gibt (passwort|None, getestet, methode) zurueck.
    progress(tested) wird periodisch aufgerufen."""
    ssid = info.get("ssid")
    if not ssid:
        return None, 0, "no-ssid"
    ap, sta = info.get("ap"), info.get("sta")
    have_pmkid = bool(info.get("pmkid"))
    have_hs = bool(info.get("anonce") and info.get("snonce") and info.get("mic") and info.get("eapol2"))
    if not have_pmkid and not have_hs:
        return None, 0, "no-handshake"
    if have_hs:
        amin, amax = (ap, sta) if ap < sta else (sta, ap)
        an, sn = info["anonce"], info["snonce"]
        nmin, nmax = (an, sn) if an < sn else (sn, an)
        bb = amin + amax + nmin + nmax
    tested = 0
    for w in words:
        if tested >= limit:
            break
        w = w.rstrip(b"\r\n")
        if len(w) < 8 or len(w) > 63:
            continue
        tested += 1
        if progress and (tested % 200 == 0):
            progress(tested)
        try:
            pmk = hashlib.pbkdf2_hmac("sha1", w, ssid, 4096, 32)
        except Exception:
            continue
        if have_pmkid:
            calc = hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16]
            if calc == info["pmkid"]:
                return w.decode("utf-8", "replace"), tested, "pmkid"
        if have_hs:
            kck = _prf512(pmk, b"Pairwise key expansion", bb)[:16]
            if info["kver"] == 1:
                m = hmac.new(kck, info["eapol2"], hashlib.md5).digest()
            else:
                m = hmac.new(kck, info["eapol2"], hashlib.sha1).digest()[:16]
            if m == info["mic"]:
                return w.decode("utf-8", "replace"), tested, "handshake"
    return None, tested, "not-found"


# Kompakte Liste haeufiger WLAN-/WPA-Passwoerter (>=8 Zeichen relevant) — fuer "ohne Wortliste".
BUILTIN_COMMON = [
    "12345678", "123456789", "1234567890", "password", "password1", "passwort",
    "qwertz123", "qwertzuiop", "qwerty123", "administrator", "admin123", "adminadmin",
    "welcome1", "internet", "wlan1234", "wlanpasswort", "geheim123", "changeme",
    "letmein123", "iloveyou1", "sonnenschein", "fussball", "deutschland", "0123456789",
    "11111111", "00000000", "88888888", "12341234", "123123123", "abc12345",
    "passw0rd", "P@ssw0rd", "Sommer2024", "Sommer2025", "Winter2024", "Winter2025",
    "familie123", "hallo123", "test1234", "master123", "superman1", "batman123",
    "dragon123", "monkey123", "shadow123", "trustno1", "starwars1", "michael1",
    "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "!QAZ2wsx", "qazwsxedc", "asdfghjkl",
    "computer1", "freedom01", "whatever1", "princess1", "sunshine1", "football1",
]


def _digits_gen(lo, hi, cap):
    import itertools
    n = 0
    for L in range(lo, hi + 1):
        for tup in itertools.product(b"0123456789", repeat=L):
            yield bytes(tup)
            n += 1
            if n >= cap:
                return


def iter_words(body, cap):
    """Kandidatenquelle je nach mode: path | text | common | digits."""
    mode = body.get("mode") or ("path" if body.get("wordlist_path") else "common")
    if mode == "path":
        p = body.get("wordlist_path", "")
        if p and os.path.isfile(p):
            with open(p, "rb") as fh:
                for line in fh:
                    yield line
        return
    if mode == "text" or body.get("wordlist_text"):
        for line in (body.get("wordlist_text") or "").split("\n"):
            yield line.encode("utf-8", "replace")
        return
    if mode == "digits":
        lo = max(8, int(body.get("dmin", 8)))
        hi = min(12, int(body.get("dmax", 8)))
        for w in _digits_gen(lo, hi, cap):
            yield w
        return
    if mode == "mask":
        import re
        mask = body.get("mask", "") or ""
        if re.fullmatch(r"(\?d)+", mask):     # reine Ziffern-Maske -> CPU kann das
            L = len(mask) // 2
            for w in _digits_gen(L, L, cap):
                yield w
        return                                # Buchstaben-Maske: CPU liefert nichts (nur hashcat)
    for w in BUILTIN_COMMON:      # default: eingebaute Liste
        yield w.encode("utf-8")


# ---------------- Job-Verwaltung + GPU (hashcat) ----------------
import threading
import time
import shutil
import subprocess
import tempfile

JOBS = {}
JOB_LOCK = threading.Lock()
_JOB_SEQ = [0]


def _new_job():
    with JOB_LOCK:
        _JOB_SEQ[0] += 1
        jid = "j%d" % _JOB_SEQ[0]
        JOBS[jid] = {"tested": 0, "total": 0, "rate": 0, "found": False,
                     "password": None, "done": False, "method": "", "engine": "", "error": None}
    return jid


def _jset(jid, **kw):
    with JOB_LOCK:
        if jid in JOBS:
            JOBS[jid].update(kw)


def build_hc22000(info):
    """Baut eine hashcat-22000-Zeile aus PMKID oder 4-Way. None wenn nichts da."""
    ssid = info.get("ssid")
    ap, sta = info.get("ap"), info.get("sta")
    if not ssid or not ap or not sta:
        return None
    eh = ssid.hex()
    if info.get("pmkid"):
        return "WPA*01*%s*%s*%s*%s***" % (info["pmkid"].hex(), ap.hex(), sta.hex(), eh)
    if info.get("mic") and info.get("anonce") and info.get("eapol2"):
        # TYPE 02: MIC*AP*STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR(00)
        return "WPA*02*%s*%s*%s*%s*%s*%s*00" % (
            info["mic"].hex(), ap.hex(), sta.hex(), eh,
            info["anonce"].hex(), info["eapol2"].hex())
    return None


def _digits_total(lo, hi):
    return sum(10 ** L for L in range(lo, hi + 1))


def job_cpu(jid, info, body, cap):
    t0 = time.time()
    # Gesamtzahl fuer Prozent (soweit bekannt)
    mode = body.get("mode") or ("path" if body.get("wordlist_path") else "common")
    if mode == "digits":
        total = min(cap, _digits_total(max(8, int(body.get("dmin", 8))), min(12, int(body.get("dmax", 8)))))
    elif mode == "common":
        total = len(BUILTIN_COMMON)
    else:
        total = 0
    _jset(jid, total=total)

    def prog(n):
        _jset(jid, tested=n, rate=int(n / max(0.001, time.time() - t0)))
    try:
        pw, tested, how = crack(info, iter_words(body, cap), cap, prog)
        _jset(jid, done=True, found=pw is not None, password=pw, tested=tested,
              method=how, rate=int(tested / max(0.001, time.time() - t0)))
    except Exception as e:
        _jset(jid, done=True, error=str(e))


def job_hashcat(jid, info, body, cap):
    """GPU/optimiert via hashcat. Faellt bei Fehler auf CPU zurueck."""
    hashline = build_hc22000(info)
    if not hashline:
        _jset(jid, done=True, error="kein PMKID/Handshake fuer hashcat")
        return
    tmp = tempfile.mkdtemp(prefix="mcc_")
    hf = os.path.join(tmp, "h.hc22000")
    outf = os.path.join(tmp, "out.txt")
    with open(hf, "w") as f:
        f.write(hashline + "\n")
    mode = body.get("mode") or ("path" if body.get("wordlist_path") else "common")
    cmd = [hashcat_bin(), "-m", "22000", "-o", outf, "--potfile-disable",
           "--status", "--status-timer", "1", "--machine-readable"]
    if mode == "mask":
        cmd += ["-a", "3", hf, body.get("mask") or "?d?d?d?d?d?d?d?d"]
    elif mode == "digits":
        lo = max(8, int(body.get("dmin", 8)))
        cmd += ["-a", "3", hf, "?d" * lo]
    elif mode == "path" and body.get("wordlist_path") and os.path.isfile(body["wordlist_path"]):
        cmd += ["-a", "0", hf, body["wordlist_path"]]
    else:
        wl = os.path.join(tmp, "wl.txt")
        with open(wl, "w") as f:
            f.write("\n".join(BUILTIN_COMMON))
        cmd += ["-a", "0", hf, wl]
    try:
        # WICHTIG: hashcat aus SEINEM Ordner starten, sonst findet es OpenCL/kernels nicht (0 Hashes).
        hcdir = os.path.dirname(hashcat_bin() or "")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             cwd=hcdir or None)
        for line in p.stdout:
            parts = line.strip().split("\t")
            # machine-readable: STATUS <n> ... PROGRESS <done> <total> ...
            if "PROGRESS" in parts:
                try:
                    i = parts.index("PROGRESS")
                    done_, total_ = int(parts[i + 1]), int(parts[i + 2])
                    _jset(jid, tested=done_, total=total_)
                except Exception:
                    pass
        p.wait()
        pw = None
        if os.path.isfile(outf):
            with open(outf) as f:
                data = f.read().strip()
            if data and ":" in data:
                pw = data.rsplit(":", 1)[-1]
        _jset(jid, done=True, found=pw is not None, password=pw, method="hashcat")
    except Exception as e:
        _jset(jid, done=True, error="hashcat-Fehler: %s" % e)


HASHCAT_BIN = None


def hashcat_bin():
    """Pfad zum hashcat-Binary: gesetzt > PATH > bereits entpacktes ./tools."""
    if HASHCAT_BIN and os.path.isfile(HASHCAT_BIN) and (os.name != "nt" or HASHCAT_BIN.lower().endswith(".exe")):
        return HASHCAT_BIN
    w = shutil.which("hashcat")
    if w:
        return w
    want = "hashcat.exe" if os.name == "nt" else "hashcat.bin"   # plattformrichtige Binary!
    tools = os.path.join(os.getcwd(), "tools")
    if os.path.isdir(tools):
        for root, _, files in os.walk(tools):
            for fn in files:
                if fn.lower() == want:
                    return os.path.join(root, fn)
    return None


def install_hashcat():
    """Laedt das neueste hashcat-Release (.7z) von GitHub und entpackt es nach ./tools."""
    api = "https://api.github.com/repos/hashcat/hashcat/releases/latest"
    req = urllib.request.Request(api, headers={"User-Agent": "MCC", "Accept": "application/vnd.github+json"})
    rel = json.loads(urllib.request.urlopen(req, timeout=30).read())
    asset = next((a for a in rel.get("assets", [])
                  if a["name"].endswith(".7z") and a["name"].startswith("hashcat-")), None)
    if not asset:
        raise RuntimeError("kein hashcat-.7z-Asset gefunden")
    tools = os.path.join(os.getcwd(), "tools")
    os.makedirs(tools, exist_ok=True)
    arc = os.path.join(tools, asset["name"])
    with urllib.request.urlopen(urllib.request.Request(asset["browser_download_url"],
                                headers={"User-Agent": "MCC"}), timeout=600) as r, open(arc, "wb") as f:
        shutil.copyfileobj(r, f)
    # Entpacken: 7z falls vorhanden, sonst tar (Windows 10+ bsdtar kann .7z lesen)
    ok = False
    for cmd in (["7z", "x", "-y", "-o" + tools, arc], ["tar", "-xf", arc, "-C", tools]):
        try:
            if cmd[0] == "tar" or shutil.which(cmd[0]):
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                ok = True
                break
        except Exception:
            continue
    if not ok:
        raise RuntimeError("Entpacken fehlgeschlagen (7z/tar fehlt). Archiv liegt unter: " + arc)
    want = "hashcat.exe" if os.name == "nt" else "hashcat.bin"   # plattformrichtig, sonst WinError 193
    fallback = None
    for root, _, files in os.walk(tools):
        for fn in files:
            low = fn.lower()
            if low == want:
                return os.path.join(root, fn)
            if low in ("hashcat.exe", "hashcat.bin"):
                fallback = fallback or os.path.join(root, fn)
    if fallback:
        return fallback
    raise RuntimeError("hashcat-Binary nach Entpacken nicht gefunden")


def job_install(jid):
    global HASHCAT_BIN
    try:
        _jset(jid, method="download+entpacken laeuft (~50 MB)...")
        binp = install_hashcat()
        HASHCAT_BIN = binp
        _jset(jid, done=True, found=True, password=binp, method="installiert")
    except Exception as e:
        _jset(jid, done=True, error=str(e))


def job_rockyou(jid):
    """Laedt rockyou.txt (~134 MB, 14 Mio Passwoerter) von GitHub nach ./tools."""
    try:
        url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        tools = os.path.join(os.getcwd(), "tools")
        os.makedirs(tools, exist_ok=True)
        dst = os.path.join(tools, "rockyou.txt")
        _jset(jid, method="download rockyou.txt (~134 MB)...")
        req = urllib.request.Request(url, headers={"User-Agent": "MCC"})
        with urllib.request.urlopen(req, timeout=900) as r:
            _jset(jid, total=int(r.headers.get("Content-Length", "0")))
            got = 0
            with open(dst, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    got += len(chunk)
                    _jset(jid, tested=got)
        _jset(jid, done=True, found=True, password=dst, method="rockyou")
    except Exception as e:
        _jset(jid, done=True, error=str(e))


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/proxy?"):
            return self._proxy()
        if self.path.startswith("/crack_status"):
            return self._crack_status()
        if self.path.startswith("/pentool?"):
            return self._pentool("GET")
        return super().do_GET()

    def _pentool(self, method):
        """Proxy zu einem lokalen ESP32-Pentest-Tool (HTTP, z.B. risinek @192.168.4.1).
        Nur private/lokale Hosts (kein offener Proxy). Umgeht CORS."""
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        url = qs.get("url", [""])[0]
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        priv = host in ("localhost",) or bool(re.match(
            r"^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)", host))
        if not (url.lower().startswith("http://") and priv):
            self.send_error(403, "nur lokale/private Hosts erlaubt")
            return
        try:
            data = None
            if method == "POST":
                ln = int(self.headers.get("Content-Length", "0"))
                data = self.rfile.read(ln) if ln else b""
            req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "MCC"})
            with urllib.request.urlopen(req, timeout=30) as up:
                body = up.read()
                ct = up.headers.get("Content-Type", "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_error(502, "Pentool-Fehler: %s" % e)

    def _send_json(self, obj, code=200):
        out = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(out)

    def _crack_status(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        jid = qs.get("id", [""])[0]
        with JOB_LOCK:
            job = dict(JOBS.get(jid, {})) if jid in JOBS else None
        self._send_json(job or {"error": "unbekannter Job"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/install_hashcat":
            jid = _new_job()
            _jset(jid, engine="hashcat-Installer", method="starte...")
            threading.Thread(target=job_install, args=(jid,), daemon=True).start()
            self._send_json({"ok": True, "job_id": jid})
            return
        if path == "/get_rockyou":
            jid = _new_job()
            _jset(jid, engine="rockyou-Download", method="starte...")
            threading.Thread(target=job_rockyou, args=(jid,), daemon=True).start()
            self._send_json({"ok": True, "job_id": jid})
            return
        if path == "/pentool":
            return self._pentool("POST")
        if path != "/crack":
            self.send_error(404)
            return
        try:
            ln = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(ln).decode("utf-8"))
            import re as _re
            if (body.get("mode") == "mask" and hashcat_bin() is None
                    and not _re.fullmatch(r"(\?d)+", body.get("mask", "") or "")):
                self._send_json({"ok": False, "error": "Buchstaben-Maske braucht hashcat/GPU. Ohne hashcat nur reine Ziffern-Maske (?d) — oder hashcat installieren."})
                return
            pcap = base64.b64decode(body.get("pcap_b64", ""))
            info = extract_wpa(parse_pcap(pcap))
            ssid_override = (body.get("ssid") or "").strip()
            if ssid_override:
                info["ssid"] = ssid_override.encode("utf-8")
            have_pmkid = bool(info["pmkid"])
            have_hs = bool(info["anonce"] and info["snonce"] and info["mic"])
            if not info["ssid"]:
                self._send_json({"ok": False, "error": "keine SSID (im PCAP kein Beacon) — SSID oben eintragen"})
                return
            if not have_pmkid and not have_hs:
                dbg = pcap_debug(pcap)
                self._send_json({"ok": False,
                                 "error": "kein PMKID/Handshake gefunden — Debug: " + json.dumps(dbg),
                                 "debug": dbg})
                return
            cap = int(body.get("limit", 5000000))
            use_gpu = (hashcat_bin() is not None) and (body.get("engine") != "cpu")
            jid = _new_job()
            _jset(jid, engine=("hashcat/GPU" if use_gpu else "python/CPU"),
                  ssid=info["ssid"].decode("utf-8", "replace"),
                  have_pmkid=have_pmkid, have_handshake=have_hs)
            target = job_hashcat if use_gpu else job_cpu
            threading.Thread(target=target, args=(jid, info, body, cap), daemon=True).start()
            self._send_json({"ok": True, "job_id": jid, "engine": ("hashcat/GPU" if use_gpu else "python/CPU"),
                             "have_pmkid": have_pmkid, "have_handshake": have_hs,
                             "ssid": info["ssid"].decode("utf-8", "replace")})
        except Exception as e:
            self._send_json({"ok": False, "error": str(e)})

    def _proxy(self):
        qs = urllib.parse.urlparse(self.path).query
        url = urllib.parse.parse_qs(qs).get("url", [""])[0]
        host = urllib.parse.urlparse(url).hostname or ""

        # fail-closed: nur erlaubte Hosts, nur https
        if not url.lower().startswith("https://") or not host_allowed(host):
            self.send_error(403, "Host nicht erlaubt")
            return

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MCC-Proxy"})
            with urllib.request.urlopen(req, timeout=60) as up:
                data = up.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:  # explizit: Fehler an den Client melden, nicht schlucken
            self.send_error(502, "Proxy-Fehler: %s" % e)

    def end_headers(self):
        # API-Endpunkte setzen ACAO selbst -> hier nur fuer statische Dateien, sonst doppelter Header
        api = self.path.startswith(("/proxy", "/crack", "/pentool", "/install_hashcat", "/get_rockyou"))
        if not api:
            self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        print("Marauder Control Center: http://localhost:%d" % PORT)
        print("Firmware-Proxy aktiv unter /proxy?url=... (nur github.com/githubusercontent.com)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nBeendet.")
