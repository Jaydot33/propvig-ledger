#!/usr/bin/env python3
"""Verify the propvig public ledger yourself. Stdlib only — no dependencies.

    python3 verify.py

It recomputes, from scratch, the SHA-256 of every sealed day and walks the hash chain.
If any day's picks/results were edited, deleted, or re-ordered after sealing, that day's
content hash stops matching and every day after it breaks — visibly. Don't trust our
checkmark; run this and check for yourself.
"""
import json, hashlib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = os.path.join(HERE, "locked")
GENESIS = "0" * 64

def content_hash(content):
    # identical rule the sealing process uses: SHA-256 of the canonical JSON of `content`
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

def main():
    ledger_path = os.path.join(LOCK, "ledger.hash")
    lines = [l for l in open(ledger_path).read().splitlines() if l.strip()]
    prev = GENESIS
    ok = True
    for line in lines:
        date, ch_ledger, chain_ledger, prev_field = line.split("\t")
        doc = json.load(open(os.path.join(LOCK, f"{date}.json")))
        ch = content_hash(doc["content"])
        chain = hashlib.sha256((prev + ch).encode()).hexdigest()

        if ch != doc.get("content_hash"):
            print(f"CHANGED  {date}: this day's file was edited after sealing "
                  f"(recomputed {ch[:12]} != sealed {str(doc.get('content_hash'))[:12]})")
            ok = False
        elif ch != ch_ledger:
            print(f"MISMATCH {date}: content hash differs from the chain ledger")
            ok = False
        elif chain != chain_ledger:
            print(f"BROKEN   {date}: chain link does not follow the previous day")
            ok = False
        else:
            print(f"ok       {date}  content {ch[:12]}  chain {chain[:12]}")
        prev = chain_ledger  # follow the published chain so we localize the first break

    print()
    if ok:
        print(f"CHAIN INTACT — {len(lines)} sealed day(s) verify. "
              f"Nothing has been edited since each day was locked.")
    else:
        print("CHAIN BROKEN — at least one sealed day was altered after the fact (see above).")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
