"""Erzeugt eine Standard-Partitionstabelle (16 MB, OTA, App @0x10000) -> fwparts/partitions.bin"""
import struct, hashlib, os

parts = [
    # name,      type(0=app,1=data), subtype, offset,   size
    ("nvs",      1, 0x02, 0x009000, 0x005000),
    ("otadata",  1, 0x00, 0x00e000, 0x002000),
    ("app0",     0, 0x10, 0x010000, 0x300000),
    ("app1",     0, 0x11, 0x310000, 0x300000),
    ("spiffs",   1, 0x82, 0x610000, 0x9E0000),
    ("coredump", 1, 0x03, 0xFF0000, 0x010000),
]

MAGIC = b"\xAA\x50"
blob = b""
for name, t, st, off, size in parts:
    label = name.encode()[:16].ljust(16, b"\x00")
    blob += MAGIC + struct.pack("<BB", t, st) + struct.pack("<II", off, size) + label + struct.pack("<I", 0)

blob += b"\xEB\xEB" + b"\xFF" * 14 + hashlib.md5(blob).digest()
blob = blob.ljust(0xC00, b"\xFF")

out = os.path.join(os.path.dirname(__file__), "..", "fwparts", "partitions.bin")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "wb") as f:
    f.write(blob)
print("partitions.bin", len(blob), "bytes,", len(parts), "entries")
