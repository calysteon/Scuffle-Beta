#!/usr/bin/env python3
"""Download the KNOWN-VULNERABLE mqqm.dll (10.0.22621.963, pre-April-2023 patch) from Microsoft's own
symbol server. This is the demo target binary. Safe: the CVE (2023-21554) is long patched; we run a
deliberately down-level copy in isolation for a repeatable reproduction.

  python3 fetch_vuln_mqqm.py            # writes ./mqqm.dll (x64, 22621.963)
"""
import urllib.request, os, sys
# version 10.0.22621.963 x64  ->  symbol-server path = <PE timestamp><PE virtualSize>, both hex
URL = "https://msdl.microsoft.com/download/symbols/mqqm.dll/60F7BC3F153000/mqqm.dll"
OUT = sys.argv[1] if len(sys.argv) > 1 else "mqqm.dll"
req = urllib.request.Request(URL, headers={"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"})
with urllib.request.urlopen(req, timeout=180) as r, open(OUT, "wb") as f:
    f.write(r.read())
print(f"[fetch] wrote {OUT} ({os.path.getsize(OUT)} bytes) = mqqm.dll 10.0.22621.963 (vulnerable)")
