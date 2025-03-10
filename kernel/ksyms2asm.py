#!/usr/bin/env python3

"""Kallsyms to Asm

Usage:
    ksyms2obj.py <kallsyms> <output file>
"""

from docopt import docopt
opts = docopt(__doc__)

with open(opts["<kallsyms>"], "r") as f:
    symbols = f.read().strip().split("\n")


symbols = [s.strip().split(" ") for s in symbols]
symbols.sort(key=lambda x: int(x[0], 16))

base = int(symbols[0][0], 16)


with open(opts["<output file>"], "w") as f:
    offset_prev = -1
    symbols_seen = set()
    for sym in symbols:
        addr, t, name = sym

        t = t.upper()
        if t not in "TBD": continue # symbol of unimplemented type
        if "\t" in name: continue  # symbol not in vmlinux
        
        if name not in symbols_seen:
            symbols_seen.add(name)
        else:
            continue

        offset = hex(int(addr, 16) - base)

        _t = "function" if t == "T" else "object"

        if offset != offset_prev:
            f.write(f".org {offset}\n")

        f.write(f".globl {name}\n")
        f.write(f".type {name}, @{_t}\n")
        f.write(f"{name}:\n")
        f.write("\tnop\n")
        f.write(f"\t.size {name}, 0\n\n")

        offset_prev = offset
