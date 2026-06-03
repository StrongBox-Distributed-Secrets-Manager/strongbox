#!/usr/bin/env python3
import os
import secrets
import sys

# GF(2^8) irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b)
IRREDUCIBLE = 0x11b

def gf_mul(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= IRREDUCIBLE
        b >>= 1
    return p & 0xFF

def gf_inv(a):
    # Simple brute force inversion in GF(2^8)
    for i in range(256):
        if gf_mul(a, i) == 1:
            return i
    return 0

def eval_poly(coeffs, x):
    y = 0
    power = 1
    for c in coeffs:
        y ^= gf_mul(c, power)
        power = gf_mul(power, x)
    return y

def split(secret_hex, threshold, shares_count):
    secret = bytes.fromhex(secret_hex)
    out = [[] for _ in range(shares_count)]
    for b in secret:
        # Generate random coefficients for the polynomial: f(x) = a_0 + a_1*x + ... + a_{k-1}*x^{k-1}
        # a_0 is the byte of the secret
        coeffs = [b] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(1, shares_count + 1):
            out[i - 1].append(eval_poly(coeffs, i))

    for i, vals in enumerate(out, 1):
        print(f"{i}-" + ",".join(map(str, vals)))

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
            # Lagrange interpolation: L_j(x) = prod( (x - xm) / (xj - xm) )
            # We need L_j(0) = prod( (-xm) / (xj - xm) )
            num = 1
            den = 1
            for m, (xm, _) in enumerate(parsed):
                if m == j:
                    continue
                # In GF(2^8), addition/subtraction is XOR
                num = gf_mul(num, xm)
                den = gf_mul(den, xj ^ xm)

            term = gf_mul(valsj[byte_index], gf_mul(num, gf_inv(den)))
            accum ^= term
        result.append(accum)

    sys.stdout.write(result.hex())
    # Clear local copies of reconstructed data
    for i in range(len(parsed)):
        parsed[i] = (0, [0] * length)

def main():
    if len(sys.argv) < 2:
        print("usage: shamir.py split HEX K N | recover SHARE...")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "split":
        split(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif mode == "recover":
        recover(sys.argv[2:])
    else:
        print("usage: shamir.py split HEX K N | recover SHARE...")
        sys.exit(1)

if __name__ == "__main__":
    main()