#!/usr/bin/env python3
"""BOLT #11 Lightning invoice decoder — pure Python, zero dependencies.

Decodes Lightning Network payment requests like::

    lnbc2500u1...

and reports the network, amount, timestamp, payment hash, description,
expiry, min_final_cltv_expiry, payee node key, routing hints and the
signature bytes.

Checks performed: bech32 checksum, invoice structure, tagged-field
bounds, padding bits, amount sanity. The signature is *decoded*, not
cryptographically verified (that needs secp256k1 ECDSA recovery,
deliberately out of scope for this tiny decoder).

>>> inv = demo_invoice()
>>> inv.startswith("lnbc2500u1")
True
>>> d = decode(inv)
>>> d["network"]
'mainnet'
>>> d["amount_msat"]
250000000
>>> d["timestamp"]
1699000000
>>> d["expiry"]
86400
>>> d["min_final_cltv_expiry"]
18
>>> d["payment_hash"] == bytes(range(32)).hex()
True
>>> d["description"]
'Two coffees at the lightning meetup'
>>> len(d["signature"]["r"]), len(d["signature"]["s"])
(64, 64)

A tampered invoice fails the checksum:

>>> decode(inv[:-1] + ("q" if inv[-1] != "q" else "p"))
Traceback (most recent call last):
...
ValueError: bech32 checksum mismatch

An unknown network prefix is rejected:

>>> _, data = bech32_decode(demo_invoice())
>>> decode(_bech32_encode("lnzz", data))
Traceback (most recent call last):
...
ValueError: unknown network prefix: 'zz'
"""

from __future__ import annotations

import argparse
import doctest
import sys

# ---------------------------------------------------------------------------
# bech32 (self-contained, BIP-173)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _BECH32_GEN[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(s):
    """Split a bech32 string into (hrp, data_groups), verifying the checksum."""
    s = s.strip().lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 7089:
        raise ValueError("bad bech32 separator position")
    hrp, rest = s[:pos], s[pos + 1:]
    data = [_BECH32_CHARSET.find(c) for c in rest]
    if any(v < 0 for v in data):
        raise ValueError("invalid bech32 character")
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ValueError("bech32 checksum mismatch")
    return hrp, data[:-6]


def _bech32_encode(hrp, data):
    values = _bech32_hrp_expand(hrp) + list(data)
    polymod = _bech32_polymod(values + [0] * 6) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[v] for v in list(data) + checksum)


# ---------------------------------------------------------------------------
# bit helpers
# ---------------------------------------------------------------------------

def _convert_bits(data, frombits, tobits, pad):
    """Regroup bits, e.g. 5-bit bech32 groups <-> 8-bit bytes."""
    acc = bits = 0
    out = bytearray()
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or v >> frombits:
            raise ValueError("invalid data value")
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding bits")
    return bytes(out)


def _groups_to_int(groups):
    n = 0
    for g in groups:
        n = (n << 5) | g
    return n


def _int_to_groups(n, length):
    if n < 0 or n >= (1 << (5 * length)):
        raise ValueError("integer does not fit in %d groups" % length)
    return [(n >> (5 * (length - 1 - i))) & 31 for i in range(length)]


# ---------------------------------------------------------------------------
# BOLT11 parsing
# ---------------------------------------------------------------------------

_NETWORKS = (("bcrt", "regtest"), ("tbs", "signet"), ("bc", "mainnet"),
             ("tb", "testnet"), ("sb", "simnet"))
# amount multiplier -> tenth-of-millisatoshi per unit (pico is sub-msat)
_TENTH_MSAT_PER_UNIT = {"m": 1_000_000_000, "u": 1_000_000, "n": 1_000, "p": 1}

_DEFAULT_EXPIRY = 3600           # BOLT11 default: 1 hour
_DEFAULT_MIN_FINAL_CLTV = 18     # BOLT11 default


def _parse_hrp(hrp):
    """Return (network, amount_msat or None) from the human-readable part."""
    if not hrp.startswith("ln"):
        raise ValueError("not a lightning invoice hrp: %r" % hrp)
    rest = hrp[2:]
    network = None
    for prefix, name in _NETWORKS:
        if rest.startswith(prefix):
            network, rest = name, rest[len(prefix):]
            break
    if network is None:
        raise ValueError("unknown network prefix: %r" % hrp[2:])
    amount_msat = None
    if rest:
        mult, digits = rest[-1], rest[:-1]
        bad = (mult not in _TENTH_MSAT_PER_UNIT or not digits
               or not digits.isdigit()
               or (len(digits) > 1 and digits.startswith("0")))
        if bad:
            raise ValueError("bad amount in hrp: %r" % hrp)
        tenth_msat = int(digits) * _TENTH_MSAT_PER_UNIT[mult]
        if tenth_msat % 10:
            raise ValueError("amount is not a whole number of millisatoshis")
        amount_msat = tenth_msat // 10
    return network, amount_msat


def decode(invoice):
    """Decode a BOLT11 invoice string into a plain dict.

    >>> d = decode(demo_invoice())
    >>> d["network"], d["amount_msat"]
    ('mainnet', 250000000)
    """
    hrp, data = bech32_decode(invoice)
    network, amount_msat = _parse_hrp(hrp)
    if len(data) < 7 + 104:  # timestamp + signature
        raise ValueError("invoice data too short")

    timestamp = _groups_to_int(data[:7])
    body, sig_groups = data[7:-104], data[-104:]
    sig = _convert_bits(sig_groups, 5, 8, True)  # 65 bytes: r || s || recovery

    out = {
        "network": network,
        "amount_msat": amount_msat,
        "timestamp": timestamp,
        "expiry": _DEFAULT_EXPIRY,
        "min_final_cltv_expiry": _DEFAULT_MIN_FINAL_CLTV,
        "payment_hash": None,
        "description": None,
        "description_hash": None,
        "payee_pubkey": None,
        "fallback": None,
        "routing_hints": [],
        "signature": {"r": sig[:32].hex(), "s": sig[32:64].hex(),
                      "recovery_flag": sig[64]},
    }

    pos = 0
    while pos < len(body):
        if pos + 3 > len(body):
            raise ValueError("truncated tagged field")
        tag = body[pos]
        length = _groups_to_int(body[pos + 1:pos + 3])
        value = body[pos + 3:pos + 3 + length]
        if len(value) != length:
            raise ValueError("tagged field overruns invoice data")
        pos += 3 + length

        if tag == 1:  # 'p' payment_hash, 256 bits
            if length != 52:
                raise ValueError("payment_hash must be 52 groups")
            out["payment_hash"] = _convert_bits(value, 5, 8, False).hex()
        elif tag == 13:  # 'd' description, UTF-8 text
            out["description"] = _convert_bits(value, 5, 8, False).decode("utf-8")
        elif tag == 23:  # 'h' description_hash, 256 bits
            if length != 52:
                raise ValueError("description_hash must be 52 groups")
            out["description_hash"] = _convert_bits(value, 5, 8, False).hex()
        elif tag == 19:  # 'n' payee node key, 33 bytes
            if length != 53:
                raise ValueError("payee pubkey must be 53 groups")
            out["payee_pubkey"] = _convert_bits(value, 5, 8, False).hex()
        elif tag == 6:  # 'x' expiry, seconds
            out["expiry"] = _groups_to_int(value)
        elif tag == 24:  # 'c' min_final_cltv_expiry
            out["min_final_cltv_expiry"] = _groups_to_int(value)
        elif tag == 5:  # 'f' fallback on-chain address
            version = value[0]
            program = _convert_bits(value[1:], 5, 8, False).hex()
            out["fallback"] = {"version": version, "program": program}
        elif tag == 3:  # 'r' extra routing info (kept raw)
            out["routing_hints"].append(value)
        else:  # unknown tagged field: keep raw groups for forward compat
            out.setdefault("unknown_fields", []).append(
                {"type": _BECH32_CHARSET[tag], "groups": value})
    return out


# ---------------------------------------------------------------------------
# demo invoice (built here so the module self-tests against a valid invoice)
# ---------------------------------------------------------------------------

_DEMO_PAYMENT_HASH = bytes(range(32))
_DEMO_DESCRIPTION = "Two coffees at the lightning meetup"
_DEMO_TIMESTAMP = 1699000000
_DEMO_EXPIRY = 86400


def demo_invoice():
    """Build a fixed, valid demo invoice (its signature is all zeros).

    >>> decode(demo_invoice())["description"]
    'Two coffees at the lightning meetup'
    """
    desc_groups = _convert_bits(_DEMO_DESCRIPTION.encode(), 8, 5, True)
    phash_groups = _convert_bits(_DEMO_PAYMENT_HASH, 8, 5, True)
    fields = []
    fields += [1] + _int_to_groups(len(phash_groups), 2) + list(phash_groups)
    fields += [13] + _int_to_groups(len(desc_groups), 2) + list(desc_groups)
    fields += [6] + _int_to_groups(4, 2) + _int_to_groups(_DEMO_EXPIRY, 4)
    fields += [24] + _int_to_groups(2, 2) + _int_to_groups(_DEFAULT_MIN_FINAL_CLTV, 2)
    data = _int_to_groups(_DEMO_TIMESTAMP, 7) + fields + [0] * 104
    return _bech32_encode("lnbc2500u", data)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format(d):
    lines = [
        "network:             %s" % d["network"],
        "amount:              %s msat" % (d["amount_msat"] if d["amount_msat"] is not None else "(none)"),
        "timestamp:           %d" % d["timestamp"],
        "expiry:              %d s" % d["expiry"],
        "min_final_cltv:      %d" % d["min_final_cltv_expiry"],
        "payment_hash:        %s" % d["payment_hash"],
        "description:         %s" % d["description"],
        "description_hash:    %s" % d["description_hash"],
        "payee_pubkey:        %s" % d["payee_pubkey"],
        "fallback:            %s" % d["fallback"],
        "routing_hints:       %d" % len(d["routing_hints"]),
        "signature.r:         %s..." % d["signature"]["r"][:16],
        "signature.s:         %s..." % d["signature"]["s"][:16],
        "signature.recovery:  %d" % d["signature"]["recovery_flag"],
    ]
    if d.get("unknown_fields"):
        lines.append("unknown_fields:      %d" % len(d["unknown_fields"]))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decode a BOLT11 Lightning Network invoice.")
    ap.add_argument("invoice", nargs="?", help="invoice string (default: decode the demo)")
    ap.add_argument("--demo", action="store_true", help="print the built-in demo invoice")
    ap.add_argument("--test", action="store_true", help="run doctests")
    args = ap.parse_args(argv)
    if args.test:
        failed, n = doctest.testmod(optionflags=doctest.ELLIPSIS)
        print("%d doctests, %d failed" % (n, failed))
        return 1 if failed else 0
    if args.demo and not args.invoice:
        print(demo_invoice())
        return 0
    print(_format(decode(args.invoice or demo_invoice())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
