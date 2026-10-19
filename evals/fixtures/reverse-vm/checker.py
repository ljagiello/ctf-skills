#!/usr/bin/env python3
"""Flag checker. Usage: python3 checker.py <flag>"""

import sys

CODE = bytes.fromhex(
    "4c371536ac48177cbe616f5f4f7d1226cd7f78a7a5fb81c0580e8bb402e9fbdf3b0b9ec24116cc33318b7d4ac4713f759679776cb7910a12f55450bacd46e9dc7073b3c71a0503a52327b6c4691aa44d590d656efc2227a56e929fc79fa522599dbb28d4d558d1f868e55b94f21f2b430b33aef71133bc60617d4d72141bcf1446aea72387c95af4852800e8fdff3904808343cbca333389735fc6f2395b947c8908b5860c62f75c5ec5cf3eefcd72efad681805059b2130b8d06ba3a24a5b915b7bfead217b6c93916f9dba24fd9f6f36ded760d7e16a6e55d5f0192d4f092cd0021364ba67632943971615c9fc44afb93c85de5c4e87440ef4fffb3f1582817df6c83535487148c8c23b4c927d8be3ab830ebcf1525cc1c12aedc274aeaf98e60907ad2739bada6566a04d5da35974e07123586a9793305b"
)


def run(data: bytes) -> bool:
    code = bytes(b ^ ((i * 7 + 0x21) & 0xFF) for i, b in enumerate(CODE))
    pc, acc, ok = 0, 0, True
    while True:
        op = code[pc]
        if op == 0xF2:
            return ok
        arg = code[pc + 1]
        pc += 2
        if op == 0x6D:
            ok &= len(data) == arg
        elif op == 0x3A:
            acc = data[arg] if arg < len(data) else 0
        elif op == 0x91:
            acc ^= arg
        elif op == 0x5C:
            acc = (acc + arg) & 0xFF
        elif op == 0xE7:
            acc = ((acc << arg) | (acc >> (8 - arg))) & 0xFF
        elif op == 0x08:
            ok &= acc == arg
        else:
            raise SystemExit("bad opcode")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    print("Correct!" if run(sys.argv[1].encode()) else "Wrong.")
