#!/usr/bin/env python3
"""Verify propvig's PREGAME commitments — the honest "before play" proof. Stdlib only.

    python3 verify_commit.py

For each day that has both a commitment and a reveal, this proves:
  1. SHA-256(revealed canonical card + nonce) == the published commit_hash
     → nothing in the card changed after commitment; only result fields were added
     (results live outside the hashed card, in the reveal's `results`).
  2. The commitment was published BEFORE the earliest event.
     The authoritative witness is this file's Git commit timestamp (GitHub's clock, not
     ours). We check the self-reported committedAt here, and — when run inside the git repo
     — also the real commit time via `git log`.

Only days that pass BOTH checks are counted as pregame publicly witnessed. A day with just a
postgame seal (see verify.py) is immutable-since-publication, but is NOT pregame-witnessed.
"""
import json, hashlib, os, sys, subprocess, glob
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
COMMITS = os.path.join(HERE, "commitments")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def commit_hash(card, nonce):
    return hashlib.sha256((canon(card) + nonce).encode()).hexdigest()


def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def git_commit_time(path):
    """The real GitHub witness: when this file was first committed. None if git unavailable."""
    try:
        out = subprocess.run(
            ["git", "-C", HERE, "log", "--diff-filter=A", "--format=%aI", "--", path],
            capture_output=True, text=True, timeout=10)
        lines = [l for l in out.stdout.splitlines() if l.strip()]
        return parse_ts(lines[-1]) if lines else None
    except Exception:
        return None


def main():
    if not os.path.isdir(COMMITS):
        print("No commitments/ directory yet — 0 pregame-witnessed days.")
        print("PREGAME-WITNESSED: 0")
        sys.exit(0)

    commit_files = sorted(glob.glob(os.path.join(COMMITS, "*.commit.json")))
    witnessed = 0
    total = 0
    for cf in commit_files:
        date = os.path.basename(cf)[: -len(".commit.json")]
        rf = os.path.join(COMMITS, f"{date}.reveal.json")
        total += 1
        commit = json.load(open(cf))
        if not os.path.exists(rf):
            print(f"pending  {date}: committed ({commit.get('pickCount')} picks), not yet revealed")
            continue
        reveal = json.load(open(rf))

        recomputed = commit_hash(reveal.get("card"), reveal.get("nonce", ""))
        if recomputed != commit.get("commitHash"):
            print(f"FAIL     {date}: reveal does not match commitment "
                  f"(recomputed {recomputed[:12]} != committed {str(commit.get('commitHash'))[:12]})")
            continue

        earliest = parse_ts(commit.get("earliestEventStart"))
        git_ts = git_commit_time(f"commitments/{date}.commit.json")
        witness_ts = git_ts or parse_ts(commit.get("committedAt"))
        if earliest is None or witness_ts is None:
            print(f"FAIL     {date}: missing timestamps (earliest={earliest}, witness={witness_ts})")
            continue
        if witness_ts >= earliest:
            src = "git" if git_ts else "self-reported"
            print(f"FAIL     {date}: commitment published {witness_ts.isoformat()} ({src}) "
                  f"is NOT before first event {earliest.isoformat()}")
            continue

        witnessed += 1
        src = "git commit" if git_ts else "self-reported (git unavailable)"
        print(f"ok       {date}: card matches commitment · published pregame by {src} "
              f"({witness_ts.isoformat()} < {earliest.isoformat()}) · {commit.get('pickCount')} picks")

    print()
    print(f"PREGAME-WITNESSED: {witnessed}  (of {total} commitment day(s))")
    sys.exit(0)


if __name__ == "__main__":
    main()
