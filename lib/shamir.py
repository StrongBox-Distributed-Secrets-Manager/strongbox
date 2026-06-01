#!/usr/bin/env python3
import os
import secrets
import sys

PRIME = 257

def eval_poly(coeffs, x):
    y = 0
    power = 1
    for c in coeffs:
        y = (y + c * power) % PRIME
        power = (power * x) % PRIME
    return y

def split(secret_hex, threshold, shares):
    secret = bytes.fromhex(secret_hex)
    out = [[] for _ in range(shares)]
    for b in secret:
        coeffs = [b] + [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
        for i in range(1, shares + 1):
            out[i - 1].append(eval_poly(coeffs, i))
    for i, vals in enumerate(out, 1):
        print(f"{i}-" + ",".join(str(v) for v in vals))

def recover(parts):
    parsed = []
    for part in parts:
        x_s, vals_s = part.split("-", 1)
        parsed.append((int(x_s), [int(v) for v in vals_s.split(",")]))
    length = len(parsed[0][1])
    result = bytearray()
    for byte_index in range(length):
        accum = 0
        for j, (xj, valsj) in enumerate(parsed):
            num = 1
            den = 1
            for m, (xm, _) in enumerate(parsed):
                if m == j:
                    continue
                num = (num * (-xm)) % PRIME
                den = (den * (xj - xm)) % PRIME
            inv = pow(den, -1, PRIME)
            accum = (accum + valsj[byte_index] * num * inv) % PRIME
        if accum == 256:
            raise ValueError("invalid recovered byte")
        result.append(accum)
    sys.stdout.write(result.hex())
    for i in range(len(parsed)):
        parsed[i] = (0, [0] * length)

def main():
    if sys.argv[1] == "split":
        split(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif sys.argv[1] == "recover":
        recover(sys.argv[2:])
    else:
        raise SystemExit("usage: shamir.py split HEX K N | recover SHARE...")

if __name__ == "__main__":
    main()
