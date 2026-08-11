# The worked example: MSMQ "QueueJumper" (CVE-2023-21554)

A screenshot of a crash, turned into a proof of concept that reproduces it, on a real
Microsoft CVE. **Safe by construction:** the CVE was patched in April 2023. We run a
deliberately down-level `mqqm.dll` (10.0.22621.963) on an isolated Windows VM, so this is
a repeatable reproduction of a fixed bug, never a live 0-day.

## What the screenshot gives us

The posted stack trace is the entire input:

```
mqsvc.exe   mqqm.dll!CQmPacket::CQmPacket   0xC0000005 (access violation)
```

Four fields. No source, no packet, no offsets. Everything else is reconstructed.

## Run it (Windows 11, Administrator)

```powershell
# 1. Fetch the known-vulnerable target binary from Microsoft's own symbol server
python setup/fetch_vuln_mqqm.py mqqm_vuln.dll

# 2. Install MSMQ and swap in the down-level DLL (idempotent; verifies the load)
powershell -ExecutionPolicy Bypass -File setup/install_and_swap.ps1 -VulnDll mqqm_vuln.dll

# 3. Reproduce: stack trace in, live crash out
python scuffle.py
```

Expected tail:

```
[5 VERIFY]   firing at live MSMQ on 127.0.0.1:1801 (oracle = ground truth)
   length=  0x8000000   mqsvc 4812 -> DOWN   *** CRASH ***
RESULT: REPRODUCED. A screenshot of a stack trace became a PoC that
        crashes MSMQ with DataLength = 0x8000000.
```

The crash is detected the honest way: the `mqsvc` PID changes or vanishes. There is no
heuristic "looks exploitable" verdict, only the service actually going down.

## Files

| file | stage | what it does |
|---|---|---|
| `scuffle.py` | orchestrator | walks the five stages on the trace and drives the local reproduction |
| `send_and_verify.py` | verify | standalone crash oracle: send the 3-frame session, watch the PID |
| `gen_packet.py` | construct | byte-exact MSMQ message builder; the one derived field is the SRMP `DataLength` |
| `kb/msmq/*.bin` | retrieve | the knowledge base: two session handshake frames + one message template |
| `setup/fetch_vuln_mqqm.py` | setup | downloads `mqqm.dll` 10.0.22621.963 from Microsoft's symbol server |
| `setup/install_and_swap.ps1` | setup | enables MSMQ, swaps the down-level DLL, verifies the load |

## Why the three frames

The bug is in packet parsing, but a single packet only completes the handshake. The crash
needs the full session in order: `establish_connection` then `connection_parameters` then
the `user_message` that carries the over-large `DataLength`. That ordering is the knowledge
the KB supplies; the model supplies the bug class; a deterministic solver supplies the number.

## Isolation checklist

- A throwaway VM with no network path to anything you care about.
- The vulnerable DLL is a **down-level** copy; do not run this against a patched or
  production host, and do not point it at a machine you do not own.
- The target is `127.0.0.1`. Keep it that way.
