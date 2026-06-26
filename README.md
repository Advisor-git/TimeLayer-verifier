# TimeLayer — offline verifier

A small, self-contained tool that **verifies a TimeLayer signed receipt offline** — with no
connection to the network — by checking its cohort signatures against the public roster of node keys.

> **Status: live network, epoch 2.** Current roster: 11 nodes, 3 independent operators,
> quorum = any 2 of 3 operators (`by_operator`, k=2).
> See `pubkeys/epoch-2/` for the full roster and per-operator keys.
>
> This verifier checks that a receipt was signed by **≥ k distinct operators from the roster**.
> It does **not** by itself prove the keys are held by unrelated independent operators — that comes
> when real, independent operators run the nodes. **No "unforgeable" guarantee is claimed yet.**

## What it checks

A receipt commits to a 32-byte **root** = `BLAKE3(domain ‖ canonical_fields)` over the receipt's
content (document digest, position in the causal chain, issuer, a nonce, the roster epoch, the
replay/shadow proof digest, and the cohort ring digest). Each cohort node **signs that root** with its
own Ed25519 key. The verifier:

1. **recomputes the root from the content** (never trusts a root supplied in the receipt);
2. checks **≥ k valid Ed25519 signatures** from **distinct** signers that are **active in the roster**
   at the receipt's epoch.

This is what closes *fabrication from scratch*: anyone with the public keys and the open algorithm can
recompute every hash, but **cannot produce k real signatures without the nodes' private keys.**

- Signatures: **Ed25519** (RFC 8032). Hash: **BLAKE3**. Serialization: explicit length-prefixed fields.
- The algorithm is fully open on purpose (Kerckhoffs): security rests on the private keys, not secrecy.

## Download

Pre-built binaries are published on the [Releases page](https://github.com/TimeLayer-OS/timelayer-verifier/releases/latest):

| Platform | File |
|----------|------|
| Linux x86-64 | `timelayer-verifier-linux-amd64` |
| macOS Apple Silicon (M1/M2/M3) | `timelayer-verifier-macos-arm64` |
| macOS Intel | `timelayer-verifier-macos-x86_64` |
| Windows x86-64 | `timelayer-verifier-windows-amd64.exe` |

**macOS / Linux — make executable after download:**
```bash
chmod +x timelayer-verifier-*
```

**macOS — first run**: right-click the binary → Open → Open (to bypass Gatekeeper on unsigned binaries).

## Build from source

```bash
cargo build --release
# binary at target/release/timelayer-verifier
```

## Use

```bash
timelayer-verifier verify <receipt.tlsig> <roster.txt> <k> [by_node|by_operator]
```

- `<receipt.tlsig>` — the signed receipt.
- `<roster.txt>` — the public roster (one line per node:
  `node_id|pubkey_hex|alg|operator|region|status|valid_from|valid_to`, with a leading `epoch=N`).
- `<k>` — required number of distinct signers.
- mode — `by_node` (distinct nodes) or `by_operator` (distinct operators; one operator = one vote).

Exit code `0` = VALID, `1` = NOT VALID.

## Test vectors (`testvectors/`)

```bash
timelayer-verifier verify testvectors/valid.tlsig  testvectors/roster.txt 6 by_operator   # -> VALID
timelayer-verifier verify testvectors/forged.tlsig testvectors/roster.txt 6 by_operator   # -> NOT VALID
```

`forged.tlsig` is a fabricated receipt signed by keys that are **not** on the roster — the canonical
"fabrication from scratch" attempt — and it verifies as **NOT VALID**. Regenerate with
`timelayer-verifier testvec gen <dir>`.

## Public keys — epoch 2

The current network roster (epoch 2, `by_operator`, k=2) is in `pubkeys/epoch-2/roster.txt`.
Per-operator key files:

| File | Nodes |
|------|-------|
| `pubkeys/epoch-2/operator-1.txt` | tl-0 (DE), tl-1 (DE), tl-9 (AT) |
| `pubkeys/epoch-2/operator-2.txt` | tl-2 (SG), tl-3 (US), tl-4 (US), tl-7 (US), tl-10 (Mac) |
| `pubkeys/epoch-2/operator-3.txt` | tl-5 (FI), tl-6 (DE), tl-8 (SG) |

To verify an epoch-2 receipt:

```bash
timelayer-verifier verify <receipt.tlsig> pubkeys/epoch-2/roster.txt 2 by_operator
```

## License

Apache 2.0 — see `LICENSE`.
