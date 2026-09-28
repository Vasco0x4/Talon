#!/usr/bin/env python3
"""Decode the XOR-encoded transport strings currently embedded in Core.c."""
import re, sys

src = open('Agent/Source/Core.c').read()

def grab(name):
    m = re.search(name + r'\[\s*\d+\s*\]\s*=\s*\{(.*?)\};', src, re.S)
    return [int(x, 0) for x in re.findall(r'0x[0-9A-Fa-f]+', m.group(1))]

for label, data_name, key_name in [
    ('UserAgent', 'CfgUaXor', 'CfgUaKey'),
    ('Host',      'CfgHostXor', 'CfgHostKey'),
    ('Endpoint',  'CfgEpXor',   'CfgEpKey'),
]:
    data, key = grab(data_name), grab(key_name)
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    print(f'{label}: {plain!r}')
