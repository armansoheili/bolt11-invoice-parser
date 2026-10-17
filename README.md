# bolt11-invoice-parser

Decode Lightning Network payment requests (BOLT #11) in pure Python — zero dependencies.

## What it does

Given an invoice like

```
lnbc2500u1pj5ftkqpp5qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8...
```

it reports:

- network (`mainnet` / `testnet` / `regtest` / `signet` / `simnet`) and amount in millisatoshis (from the human-readable part, incl. `m`/`u`/`n`/`p` multipliers)
- timestamp, expiry (default 3600 s), `min_final_cltv_expiry` (default 18)
- payment hash, description / description hash, payee node pubkey
- fallback on-chain address, extra routing hints, unknown tagged fields (kept raw for forward compatibility)
- signature bytes (`r` / `s` / recovery flag) — **decoded, not cryptographically verified**

Checks performed: bech32 checksum, structure (timestamp + tagged fields + 520-bit signature), tagged-field bounds, padding bits, amount sanity (no leading zeros, whole millisatoshis).

## Usage

```bash
python3 bolt11.py "lnbc2500u1..."   # decode an invoice
python3 bolt11.py --demo            # print a built-in demo invoice
python3 bolt11.py --test            # run the 17 doctests
```

```python
from bolt11 import decode

d = decode("lnbc2500u1...")
print(d["network"], d["amount_msat"], d["description"])
```

## How it works

A BOLT11 invoice is bech32: `ln` + network + optional amount, then 5-bit groups holding a 35-bit timestamp, a sequence of tagged fields (`type` 5 bits, `length` 10 bits, `value`), and finally a 520-bit ECDSA signature. This module implements a minimal bech32 codec, regroups the 5-bit data into bytes, and walks the tagged fields (`p`ayment hash, `d`escription, `n`ode key, `h`ash, e`x`piry, `c`ltv, `f`allback, `r`outing).

## Note

This is a learning/toy project. The signature is parsed but never verified against the payee key — always validate invoices with a real Lightning implementation before paying.
