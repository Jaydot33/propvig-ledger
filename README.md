# propvig — public proof ledger

This repository is the receipt for [propvig](https://propvig.com). Every graded pick propvig makes is sealed here, wins and losses alike, and the seal is a SHA-256 hash chain that makes editing the past impossible to hide.

**Don't trust our checkmark. Run the hash yourself.**

```
python3 verify.py
```

No dependencies — just Python 3.

## What's here

- **`locked/YYYY-MM-DD.json`** — one file per day. Each holds that day's picks and results (`content`), a `content_hash` (SHA-256 of the day's content), the previous day's chain hash (`prev_hash`), and this day's `chain_hash`.
- **`locked/ledger.hash`** — the chain: one tab-separated line per day (`date · content_hash · chain_hash · prev=previous_chain_hash`).
- **`verify.py`** — recomputes every hash from scratch and walks the chain.

## How the seal works

1. **Post before the game.** Each pick — market, line, side, model projection — is written to that day's file before first pitch.
2. **Grade after.** The result is set from the box score. Losses go in the same column as wins, same weight. Pushes stay pushes.
3. **Seal the day.** The day's `content` is hashed (SHA-256). That hash is combined with the *previous* day's chain hash to produce this day's chain hash. Each link depends on the one before it.
4. **Edit anything, break the chain.** Change a result, delete a losing row, or nudge a line, and that day's content hash no longer matches — and every day after it breaks too. `verify.py` prints exactly where.

## The independent witness

The seal proves the days are *internally consistent*. What proves *when* each day was sealed is **this repository's own commit history** — GitHub's timestamps, not ours. Compare a file's commit date to the games it covers: the picks were committed before those games were played. That's the part a record you host yourself can't fake.

## Verify a single day by hand

```python
import json, hashlib
d = json.load(open("locked/2026-07-25.json"))
h = hashlib.sha256(json.dumps(d["content"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
print(h == d["content_hash"])   # True if that day is untouched
```

Analytics and entertainment, not financial advice. 21+. If you or someone you know has a gambling problem, call 1-800-GAMBLER.
