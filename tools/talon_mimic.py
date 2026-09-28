#!/usr/bin/env python3
"""Protocol-level mimic of Talon's TransportInit/CommandDispatcher.

Replays the exact packet layout the C agent produces (see Package.c /
Transport.c) against a Havoc teamserver, to validate the C2 side and the
wire format before functional testing on the Windows VM.

Usage: python3 talon_mimic.py [host] [port] [path]
"""
import struct
import random
import ssl
import socket
import sys
import time


def i32(v):
    return struct.pack('>I', v & 0xFFFFFFFF)  # Int32ToBuffer = big-endian


def bstr(s):
    b = s.encode() if isinstance(s, str) else s
    return i32(len(b)) + b  # PackageAddBytes: [len BE][bytes]


MAGIC = b'taln'             # 'taln' == 0x74616C6E, Int32ToBuffer -> 74 61 6C 6E
CMD_REGISTER = 0x100
CMD_GET_JOB = 0x101


def build_register(agent_id):
    # TransportInit field order (must match exactly)
    body = i32(agent_id)                                   # AgentID (repeated)
    body += bstr('LABVM')                                  # ComputerName NetBIOS
    body += bstr('Administrator')                          # Username
    body += bstr('lab.local')                              # Domain (DnsDomain)
    body += bstr('10.50.100.99')                           # IpAddressList string
    body += bstr(r'C:\Windows\System32\Talon.exe')         # GetModuleFileNameA
    body += i32(4242)                                      # PID
    body += i32(0)                                         # PPID (hardcoded 0)
    body += i32(0)                                         # ProcArch (never set -> 0)
    body += i32(0)                                         # Elevated FALSE
    body += i32(10)                                        # dwMajorVersion
    body += i32(0)                                         # dwMinorVersion
    body += i32(3)                                         # wProductType WORKSTATION
    body += i32(0)                                         # wServicePackMajor
    body += i32(19045)                                     # dwBuildNumber (Win10 22H2)
    body += i32(0)                                         # OSArch (never set -> 0)
    body += i32(3)                                         # Sleeping (CONFIG_SLEEP)
    body += i32(40)                                        # Jitter (CONFIG_JITTER)
    body += i32(0)                                         # KillDate
    body += i32(0)                                         # WorkingHours

    hdr = MAGIC + i32(agent_id) + i32(CMD_REGISTER)        # PackageCreate header
    return i32(len(hdr) + len(body)) + hdr + body          # size = Length - 4


def build_getjob(agent_id):
    hdr = MAGIC + i32(agent_id) + i32(CMD_GET_JOB)
    return i32(len(hdr)) + hdr


UA = ('Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36')


def post(host, port, path, pkt):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = (f'POST {path} HTTP/1.1\r\n'
           f'Host: {host}:{port}\r\n'
           f'User-Agent: {UA}\r\n'
           f'Content-Length: {len(pkt)}\r\n'
           f'Connection: close\r\n\r\n')
    s = socket.create_connection((host, port), timeout=10)
    ss = ctx.wrap_socket(s, server_hostname=host)
    ss.sendall(req.encode('latin-1') + pkt)
    data = b''
    while True:
        chunk = ss.recv(65536)
        if not chunk:
            break
        data += chunk
    ss.close()
    head, _, body = data.partition(b'\r\n\r\n')
    return head.decode('latin-1', 'replace'), body


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 40056
    path = sys.argv[3] if len(sys.argv) > 3 else '/service-endpoint'

    agent_id = random.getrandbits(32)
    print(f'[+] agent_id = {agent_id:#010x}')

    pkt = build_register(agent_id)
    print(f'[+] REGISTER packet: {len(pkt)} bytes, first 16: {pkt[:16].hex()}')
    head, body = post(host, port, path, pkt)
    print(f'[-] response status line: {head.splitlines()[0] if head else "(empty)"}')
    print(f'[-] response body ({len(body)} bytes): {body[:64].hex()}')

    if len(body) >= 8 and body[4:8] == MAGIC:
        got = struct.unpack('<I', body[8:12])[0]   # DEREF = little-endian read
        print(f'[-] server echoed agent_id (LE read) = {got:#010x} '
              f'{"MATCH" if got == agent_id else "MISMATCH"}')
    elif len(body) >= 4:
        got = struct.unpack('>I', body[:4])[0]
        print(f'[-] first 4 bytes BE = {got:#010x}')

    # poll for jobs like the agent main loop would (2 rounds)
    for n in range(2):
        time.sleep(1)
        pkt = build_getjob(agent_id)
        head, body = post(host, port, path, pkt)
        print(f'[-] GET_JOB #{n+1}: status={head.splitlines()[0] if head else "(empty)"}, '
              f'body={len(body)} bytes {body[:32].hex()}')


if __name__ == '__main__':
    main()
