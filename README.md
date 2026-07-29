# propvig — public proof ledger

This repository is the receipt for [propvig](https://propvig.com). Every graded pick propvig makes is sealed here, wins and losses alike, and the seal is a SHA-256 hash chain that makes editing the past impossible to hide.

**Don't trust our checkmark. Run the hash yourself.**

```
python3 verify.py          # the daily seal chain (immutability since publication)
python3 verify_commit.py   # the pregame commitments (that a card pre-dated its games)
```

No dependencies — just Python 3.

## Two different proofs (don't conflate them)

1. **The seal chain** proves the daily files are *internally consistent and unchanged since they were published here*. It does **not**, on its own, prove a pick existed before its game — the daily files are committed **after grading** (they contain results).
2. **Pregame commitments** are what prove a card existed *before* the first event. See "Pregame commitments" below. This is the honest pregame witness; the seal chain is immutability-after-publication.

## What's here

- **`locked/YYYY-MM-DD.json`** — one file per day, committed after grading. Holds that day's picks and results (`content`), a `content_hash` (SHA-256 of the day's content), the previous day's chain hash (`prev_hash`), and this day's `chain_hash`.
- **`locked/ledger.hash`** — the chain: one tab-separated line per day (`date · content_hash · chain_hash · prev=previous_chain_hash`).
- **`commitments/YYYY-MM-DD.commit.json`** — a salted hash of the full card, pushed **before the first event** (hides the paid card, proves it existed).
- **`commitments/YYYY-MM-DD.reveal.json`** — the card + nonce + results, published after grading.
- **`verify.py`** — recomputes every seal hash and walks the chain.
- **`verify_commit.py`** — verifies each reveal matches its pregame commitment and that the commitment was published before the earliest event.

## How the seal works

1. **Grade after the game.** Each pick's result is set from the box score. Losses go in the same column as wins, same weight. Pushes stay pushes.
2. **Seal the day.** The day's `content` is hashed (SHA-256). That hash is combined with the *previous* day's chain hash to produce this day's chain hash. Each link depends on the one before it.
3. **Edit anything, break the chain.** Change a result, delete a losing row, or nudge a line, and that day's content hash no longer matches — and every day after it breaks too. `verify.py` prints exactly where.

The seal proves the days are internally consistent and **unchanged since publication**. It does not, by itself, prove *when* the picks were decided.

## Pregame commitments (the real "before play" proof)

A salted commitment lets us prove a card existed before its games **without revealing the paid card early**:

1. **Before the first event**, we build the canonical card — for each pick: stable pick id, player, market, line, side, model probability, Pinnacle no-vig probability, capture time, model version, and the earliest event start — generate a random `nonce`, and publish only
   `commit_hash = SHA-256(canonical_card_json + nonce)`, the card date, the pick count, and the earliest event start (`commitments/DATE.commit.json`). GitHub's commit timestamp on that file is the independent witness.
2. **After grading**, we publish the canonical card, the `nonce`, and results (`commitments/DATE.reveal.json`).
3. `verify_commit.py` proves: the revealed card + nonce hashes to the published commitment (so nothing in the card changed — only result fields were added), and the commitment file's publication pre-dates the earliest event.

Only days that pass `verify_commit.py` count as **pregame publicly witnessed**. Days published only through the postgame seal are **postgame-published** — real immutability, but not pregame proof.

## Verify a single day by hand

```python
import json, hashlib
d = json.load(open("locked/2026-07-25.json"))
h = hashlib.sha256(json.dumps(d["content"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
print(h == d["content_hash"])   # True if that day is untouched since publication
```

Analytics and entertainment, not financial advice. 21+. If you or someone you know has a gambling problem, call 1-800-GAMBLER.
