#!/usr/bin/env python3
"""Verify propvig's PREGAME commitments — the honest "before play" proof. Stdlib + `gh` only.

    python3 verify_commit.py [--state <path>]

For each day that has BOTH a commitment and a reveal this proves, and refuses to count otherwise:

  1. IMMUTABILITY. The commitment file was introduced by exactly ONE git commit and never
     amended/overwritten/re-added. Any second commit touching it is rejected. The live bytes must
     equal the bytes at that commit.

  2. TRUSTED TIME. The "published before play" witness is GitHub's SERVER-ISSUED PushEvent
     `created_at` (Events API, via `gh api`) for the push that introduced that exact commit SHA —
     GitHub's own record of when it received the push, which the pusher cannot set. No local git
     author/committer date and no self-reported `committedAt` is ever trusted. If the server
     timestamp cannot be fetched, the day FAILS CLOSED (not counted) — never assumed witnessed.
     (A GitHub Actions witness workflow can corroborate this once the repo's token has the
     `workflow` scope; it is optional — the Events API already provides the trusted timestamp.
     A previously-captured server timestamp is preserved so an aged-out event cannot un-prove a
     day whose immutability + hash + reveal integrity still verify.)

  3. ORDERING. The server timestamp must be strictly before the card's earliest event.

  4. CARD INTEGRITY. sha256(revealed canonical card + nonce) == the committed hash (nothing in
     the card changed after commitment; results live outside the hashed card).

  5. COMPLETE REVEAL. The reveal's result rows are exactly the committed official pick ids — no
     missing, no extra, no duplicate — and every result is terminal (W/L/P/Void).

Integrity failures (1, 4, 5) exit NONZERO. "Can't witness yet" states (no reveal, no server
timestamp, late push, missing earliest) are UNCOUNTED but not hard failures. The witnessed count
+ per-day verdicts are written to a machine-readable state file that the site consumes verbatim.
"""
import json, hashlib, os, sys, subprocess, glob, re
from datetime import datetime

HERE = os.environ.get("PROPVIG_LEDGER", os.path.dirname(os.path.abspath(__file__)))
COMMITS = os.path.join(HERE, "commitments")
STATE_PATH = os.environ.get("PROPVIG_WITNESS_STATE",
                            "/home/jaydot33/hr-targets/.cache/witness_state.json")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def commit_hash(card, nonce):
    return hashlib.sha256((canon(card) + str(nonce)).encode()).hexdigest()


def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def git(*args):
    return subprocess.run(["git", "-C", HERE, *args], capture_output=True, text=True, timeout=20)


def git_ok():
    """True if HERE is a usable git repo (works even on an empty repo with no commits yet)."""
    return git("rev-parse", "--git-dir").returncode == 0


def commits_touching(rel):
    """All commit SHAs that ever touched `rel`, newest first. [] if untracked or no history yet."""
    out = git("log", "--format=%H", "--", rel)
    return [l for l in out.stdout.splitlines() if l.strip()] if out.returncode == 0 else []


def bytes_at(sha, rel):
    out = git("show", f"{sha}:{rel}")
    return out.stdout if out.returncode == 0 else None


def repo_slug():
    out = git("remote", "get-url", "origin")
    if out.returncode != 0:
        return None
    m = re.search(r"github\.com[:/]+([^/]+/[^/]+?)(?:\.git)?\s*$", out.stdout.strip())
    return m.group(1) if m else None


def _sha_in_push(sha, payload):
    """True if `sha` was introduced by this push. Exact head match covers the automation (each
    commitment is pushed as a lone commit → head == sha). Otherwise fall back to a git range
    check: reachable from head, not already reachable from `before`."""
    head = payload.get("head")
    if head == sha:
        return True
    before = payload.get("before")
    if not head:
        return False
    reachable = git("merge-base", "--is-ancestor", sha, head).returncode == 0
    if not reachable:
        return False
    if before and re.fullmatch(r"0{40}", before):
        return True  # branch creation push
    if before:
        already = git("merge-base", "--is-ancestor", sha, before).returncode == 0
        return not already
    return True


def trusted_push_time(sha, slug):
    """GitHub's server-issued timestamp for the push that introduced `sha`: the PushEvent
    created_at from the Events API. The pusher cannot set it. None if unavailable (fail closed)."""
    if not slug:
        return None
    try:
        out = subprocess.run(["gh", "api", f"repos/{slug}/events?per_page=100"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return None
        events = json.loads(out.stdout) or []
        times = []
        for e in events:
            if e.get("type") != "PushEvent":
                continue
            if _sha_in_push(sha, e.get("payload") or {}):
                t = parse_ts(e.get("created_at"))
                if t:
                    times.append(t)
        return min(times) if times else None
    except Exception:
        return None


KALSHI_SET_SCHEMA = "kalshi-decision-set-v1"
KALSHI_EMPTY_ROOT = hashlib.sha256(b"[]").hexdigest()
KALSHI_META_KEYS = {"schemaVersion", "status", "count", "root", "earliestEventStart",
                    "reasonCodes"}


def canon_utf8(obj):
    """Canonical JSON with ensure_ascii=False — the producer's byte encoding.

    hrtargets freezes decision ids and set roots over UTF-8 bytes (canonical_bytes uses
    ensure_ascii=False); the ledger's own canon() ASCII-escapes. One accented player name
    in a selection string would make the two hash differently and hard-FAIL the public
    chain on ordinary data, so the Kalshi recomputations MUST use the producer's encoding.
    The card hash keeps canon() — commit_card.py hashes the card with the ASCII default,
    and changing that would break every existing commitment."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _kalshi_decision_id(payload):
    unsigned = dict(payload)
    unsigned.pop("decision_id", None)
    return hashlib.sha256(canon_utf8(unsigned).encode("utf-8")).hexdigest()


def _aware_ts(s):
    ts = parse_ts(s)
    if ts is None or ts.tzinfo is None or ts.utcoffset() is None:
        return None
    return ts


def _kalshi_set_integrity(commit, card):
    """(ok, reason) for the optional Kalshi qualification set inside a revealed card.

    Legacy cards — no Kalshi keys anywhere — verify exactly as before; this feature can
    never retroactively fail a pre-feature day. A versioned card is held to the full
    contract: exact metadata keys, recomputed decision IDs and sorted-set root, count
    agreement, commitment/card metadata binding, an earliest time that truly is the
    minimum of the decisions (a lying earliest could loosen the pregame ordering gate),
    and a degraded set that is exactly empty with its reasons recorded."""
    card_meta = card.get("kalshiDecisionSet")
    card_rows = card.get("kalshiDecisions")
    commit_meta = commit.get("kalshiDecisionSet")
    if card_meta is None and card_rows is None and commit_meta is None:
        return True, "legacy"
    if card_meta is None or card_rows is None or commit_meta is None:
        return False, "kalshi keys present on one side only (card vs commitment)"
    if not isinstance(card_meta, dict) or set(card_meta) != KALSHI_META_KEYS:
        got = sorted(card_meta) if isinstance(card_meta, dict) else "?"
        return False, f"kalshi set metadata keys {got} != required"
    if card_meta.get("schemaVersion") != KALSHI_SET_SCHEMA:
        return False, f"unknown kalshi set schema {card_meta.get('schemaVersion')!r}"
    for key in ("schemaVersion", "status", "count", "root", "reasonCodes"):
        if commit_meta.get(key) != card_meta.get(key):
            return False, f"kalshi set {key} differs between commitment and revealed card"
    status = card_meta.get("status")
    if status == "degraded":
        if (card_meta.get("count") != 0 or card_meta.get("root") != KALSHI_EMPTY_ROOT
                or card_rows != [] or not card_meta.get("reasonCodes")):
            return False, "degraded kalshi set must be exactly empty with nonempty reasonCodes"
        return True, "degraded-empty"
    if status != "ok":
        return False, f"kalshi set status {status!r} is neither ok nor degraded"
    if not isinstance(card_rows, list):
        return False, "kalshiDecisions is not a list"
    ids, starts = [], []
    for row in card_rows:
        if not isinstance(row, dict):
            return False, "kalshi decision is not an object"
        if row.get("decision_id") != _kalshi_decision_id(row):
            return False, f"kalshi decision id does not recompute ({str(row.get('decision_id'))[:12]}…)"
        ids.append(str(row["decision_id"]))
        ts = _aware_ts(row.get("event_start"))
        if ts is None:
            return False, "kalshi decision event_start missing/naive in an ok set"
        starts.append((ts, str(row.get("event_start"))))
    if len(ids) != len(set(ids)):
        return False, "duplicate kalshi decision ids"
    if ids != sorted(ids):
        return False, "kalshi decisions are not sorted by decision_id"
    if card_meta.get("count") != len(card_rows):
        return False, f"kalshi count {card_meta.get('count')} != {len(card_rows)} decisions"
    recomputed = hashlib.sha256(canon_utf8(card_rows).encode("utf-8")).hexdigest()
    if card_meta.get("root") != recomputed:
        return False, "kalshi set root does not recompute from the revealed decisions"
    if starts:
        true_earliest = min(starts, key=lambda item: item[0])[1]
        if card_meta.get("earliestEventStart") != true_earliest:
            return False, ("kalshi earliestEventStart is not the minimum of the revealed "
                           "decisions — a lying earliest could loosen the ordering gate")
    elif card_meta.get("earliestEventStart") is not None:
        return False, "empty ok set carries a non-null earliestEventStart"
    return True, "ok"


def kalshi_witnessed_ids(reveal):
    """Decision IDs eligible to count as witnessed IF the day itself is WITNESSED.
    Empty for degraded or absent sets — exclusion is the safe outcome, always."""
    card = (reveal or {}).get("card") or {}
    meta = card.get("kalshiDecisionSet") or {}
    if meta.get("status") != "ok":
        return []
    return [str(r.get("decision_id")) for r in (card.get("kalshiDecisions") or [])]


def reveal_integrity(commit, reveal):
    """Returns (ok, reason). Card hash + complete/exact/terminal results. Hard-fail checks."""
    card = reveal.get("card")
    if not isinstance(card, dict) or not isinstance(card.get("official"), list):
        return False, "reveal card missing official[] list"
    recomputed = commit_hash(card, reveal.get("nonce", ""))
    if recomputed != commit.get("commitHash"):
        return False, (f"card hash {recomputed[:12]} != committed {str(commit.get('commitHash'))[:12]} "
                       "(card changed after commitment)")
    official_ids = [p.get("id") for p in card["official"]]
    if len(official_ids) != len(set(official_ids)):
        return False, "duplicate official pick ids in card"
    results = reveal.get("results")
    if not isinstance(results, list):
        return False, "reveal has no results[]"
    res_ids = [r.get("id") for r in results]
    if len(res_ids) != len(set(res_ids)):
        return False, "duplicate result ids"
    if set(res_ids) != set(official_ids):
        extra = sorted(set(res_ids) - set(official_ids))
        missing = sorted(set(official_ids) - set(res_ids))
        return False, f"result set != official set (extra={extra[:5]}, missing={missing[:5]})"
    bad = [r.get("id") for r in results if str(r.get("result") or "").upper() not in ("W", "L", "P", "VOID")]
    if bad:
        return False, f"{len(bad)} non-terminal/null result(s): {bad[:5]}"
    kal_ok, kal_why = _kalshi_set_integrity(commit, card)
    if not kal_ok:
        return False, f"kalshi decision set: {kal_why}"
    return True, "ok"


def main():
    state = {"pregameWitnessed": 0, "dates": [], "verdicts": {},
             "trustedSource": "github Events API PushEvent.created_at (server clock)",
             "repo": None, "hardFailures": [],
             "checkedAtInfoOnly": datetime.utcnow().replace(microsecond=0).isoformat() + "Z"}

    # Prior witnessed days (sticky): once GitHub's server timestamp is captured for an immutable
    # commit, an aged-out Events API entry must not un-prove it — integrity is re-checked below.
    prior = {}
    try:
        _old = json.load(open(STATE_PATH))
        for d, v in (_old.get("verdicts") or {}).items():
            if v.get("status") == "WITNESSED" and v.get("witnessSha") and v.get("serverTimestamp"):
                prior[d] = v
    except Exception:
        prior = {}

    if not os.path.isdir(COMMITS):
        print("No commitments/ directory — 0 pregame-witnessed days.")
        _write_state(state)
        print("PREGAME-WITNESSED: 0")
        sys.exit(0)

    slug = repo_slug()
    state["repo"] = slug
    if not git_ok():
        print("FAIL: not a git repo / git unavailable — cannot establish immutability. Failing closed.")
        state["hardFailures"].append("git-unavailable")
        _write_state(state)
        sys.exit(1)

    hard_fail = False
    for cf in sorted(glob.glob(os.path.join(COMMITS, "*.commit.json"))):
        date = os.path.basename(cf)[: -len(".commit.json")]
        if not DATE_RE.match(date):
            continue  # ignore non-date files (e.g. self-tests)
        rel = f"commitments/{date}.commit.json"
        rf = os.path.join(COMMITS, f"{date}.reveal.json")
        try:
            commit = json.load(open(cf))
        except Exception as e:
            _verdict(state, date, "FAIL", f"unreadable commitment ({e})"); hard_fail = True; continue

        # (1) immutability: exactly one commit ever touched the file, bytes unchanged since.
        touches = commits_touching(rel)
        if not touches:
            _verdict(state, date, "UNCOUNTED", "commitment not yet pushed to git"); continue
        if len(touches) != 1:
            _verdict(state, date, "FAIL", f"commitment file touched by {len(touches)} commits "
                     "(expected 1) — not immutable"); hard_fail = True; continue
        witness_sha = touches[0]
        live = open(cf).read()
        if bytes_at(witness_sha, rel) != live:
            _verdict(state, date, "FAIL", "live bytes differ from the committed bytes (overwritten)")
            hard_fail = True; continue

        if not os.path.exists(rf):
            _verdict(state, date, "PENDING", f"committed ({commit.get('officialPickCount')} picks), not yet revealed",
                     sha=witness_sha); continue
        try:
            reveal = json.load(open(rf))
        except Exception as e:
            _verdict(state, date, "FAIL", f"unreadable reveal ({e})"); hard_fail = True; continue

        # (4,5) card integrity + complete/exact/terminal reveal — hard fail if broken.
        ok, why = reveal_integrity(commit, reveal)
        if not ok:
            _verdict(state, date, "FAIL", why, sha=witness_sha); hard_fail = True; continue

        # (2) trusted server timestamp (GitHub Events API) — fail closed if unavailable.
        server_ts = trusted_push_time(witness_sha, slug)
        earliest = parse_ts(commit.get("earliestEventStart"))
        if earliest is None:
            _verdict(state, date, "UNCOUNTED", "commitment has no earliestEventStart — cannot order",
                     sha=witness_sha); continue
        # durability: preserve a previously-captured server timestamp for this exact immutable
        # commit if the live event has aged out of the Events API window.
        if server_ts is None and prior.get(date, {}).get("witnessSha") == witness_sha:
            rec = parse_ts(prior[date].get("serverTimestamp"))
            if rec and rec < earliest:
                state["pregameWitnessed"] += 1; state["dates"].append(date)
                _verdict(state, date, "WITNESSED",
                         f"card matches · published pregame by GitHub server clock "
                         f"({rec.isoformat()} < {earliest.isoformat()}) · server timestamp previously "
                         f"captured (Events API), integrity re-verified · "
                         f"{commit.get('officialPickCount')} official picks",
                         sha=witness_sha, serverTs=rec.isoformat(),
                         kalshi=kalshi_witnessed_ids(reveal)); continue
        if server_ts is None:
            _verdict(state, date, "UNCOUNTED", "no GitHub server (Events API) timestamp for this "
                     "commit yet — not counted", sha=witness_sha); continue
        # (3) ordering
        if server_ts >= earliest:
            _verdict(state, date, "UNCOUNTED",
                     f"published {server_ts.isoformat()} (GitHub server) NOT before first event "
                     f"{earliest.isoformat()} — postgame, not a witness", sha=witness_sha); continue

        state["pregameWitnessed"] += 1
        state["dates"].append(date)
        _verdict(state, date, "WITNESSED",
                 f"card matches · published pregame by GitHub server clock "
                 f"({server_ts.isoformat()} < {earliest.isoformat()}) · "
                 f"{commit.get('officialPickCount')} official picks",
                 sha=witness_sha, serverTs=server_ts.isoformat(),
                 kalshi=kalshi_witnessed_ids(reveal))

    state["dates"].sort()
    _write_state(state)
    print()
    for d in sorted(state["verdicts"]):
        v = state["verdicts"][d]
        print(f"{v['status']:<10} {d}: {v['reason']}")
    print()
    print(f"PREGAME-WITNESSED: {state['pregameWitnessed']}  (of {len(state['verdicts'])} commitment day(s))")
    print(f"state -> {STATE_PATH}")
    if hard_fail:
        print("HARD FAILURE(S) present — exiting nonzero.")
        sys.exit(1)
    sys.exit(0)


def _verdict(state, date, status, reason, sha=None, serverTs=None, kalshi=None):
    state["verdicts"][date] = {"status": status, "reason": reason}
    if sha:
        state["verdicts"][date]["witnessSha"] = sha
    if serverTs:
        state["verdicts"][date]["serverTimestamp"] = serverTs
    if kalshi is not None:
        # Kalshi decisions are witnessed ONLY on a WITNESSED day with an ok set; every
        # other day contributes an empty list, and absence stays UNWITNESSED downstream.
        state["verdicts"][date]["kalshiWitnessedDecisionIds"] = list(kalshi)
        state["kalshiWitnessedDecisions"] = (state.get("kalshiWitnessedDecisions") or 0) + len(kalshi)
    if status == "FAIL":
        state["hardFailures"].append(date)


def _write_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w") as f:
            json.dump(state, f, indent=1)
    except Exception as e:
        print(f"WARN: could not write witness state to {STATE_PATH}: {e}")


if __name__ == "__main__":
    main()
