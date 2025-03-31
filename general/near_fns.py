#!/usr/bin/env python3


"""
Finds symbols Bruteforcable with Partial Overwrites

Usage:
    near_syms.py <file> <symbol>

Options:
    -h --help                   Show this screen.
"""

from docopt import docopt
opts = docopt(__doc__)

from pwn import *
context.log_level = 'error'

exe = ELF(opts["<file>"])

base_address = exe.symbols.get(opts["<symbol>"])

if not base_address:
    print("Symbol not found.")
    exit(1)


brute_none = []
brute_nibble = []
max_len = 0

for sym, address in exe.symbols.items():
    if address & ~0xff == base_address & ~0xff:
        brute_none.append((sym, address))
        max_len = max(max_len, len(sym))
    elif address & ~0xfff == base_address & ~0xfff:
        brute_nibble.append((sym, address))
        max_len = max(max_len, len(sym))

print("  No Brute Force")
for sym in brute_none:
    print(f"    {sym[0]:>{max_len}} : 0x{(sym[1] & 0xff):02x}")

print("\nNibble Brute Force")
for sym in brute_nibble:
    print(f"    {sym[0]:>{max_len}} : 0x{(sym[1] & 0xfff):03x}")
