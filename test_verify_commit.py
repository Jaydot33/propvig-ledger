#!/usr/bin/env python3
"""Stdlib tests for the Kalshi decision-set extension to the public verifier.

The one rule that cannot bend: a legacy card with no Kalshi keys verifies exactly as it
always did — 34 sealed days must not gain a new way to fail. Everything versioned is held
to recomputation: ids, sorted root, count, commitment binding, and an earliest time that
truly is the minimum of the revealed decisions.
"""
import hashlib
import json
import sys

import verify_commit as vc

fails = []


def check(name, fn):
    try:
        fn()
        print(f"  ok   {name}")
    except AssertionError as e:
        fails.append(f"{name}: {e}")
        print(f"  FAIL {name}: {e}")


def make_decision(ticker="KXMLBKS-26AUG021335PHIBAL-X-6", start="2026-08-02T17:35:00+00:00"):
    d = {"schema_version": "kalshi-decision-v1", "strategy_id": "kalshi_mlb_k_pv3_taker_v1",
         "market_ticker": ticker, "side": "NO", "model_probability": "0.6390",
         "event_start": start, "created_at": "2026-08-02T12:00:00+00:00", "eligible": True}
    d["decision_id"] = vc._kalshi_decision_id(d)
    return d


def make_versioned(decisions):
    rows = sorted(decisions, key=lambda r: r["decision_id"])
    root = hashlib.sha256(vc.canon(rows).encode()).hexdigest()
    starts = [r["event_start"] for r in rows]
    earliest = min(starts) if starts else None
    meta = {"schemaVersion": "kalshi-decision-set-v1", "status": "ok", "count": len(rows),
            "root": root, "earliestEventStart": earliest, "reasonCodes": []}
    card = {"official": [{"id": "props|1"}], "researchLeans": [],
            "kalshiDecisionSet": meta, "kalshiDecisions": rows}
    nonce = "00" * 16
    commit = {"commitHash": vc.commit_hash(card, nonce),
              "kalshiDecisionSet": {k: meta[k] for k in
                                    ("schemaVersion", "status", "count", "root", "reasonCodes")}}
    reveal = {"card": card, "nonce": nonce,
              "results": [{"id": "props|1", "result": "W"}]}
    return commit, reveal


def test_legacy_card_still_verifies():
    card = {"official": [{"id": "props|1"}], "researchLeans": []}
    nonce = "11" * 16
    commit = {"commitHash": vc.commit_hash(card, nonce)}
    reveal = {"card": card, "nonce": nonce, "results": [{"id": "props|1", "result": "L"}]}
    ok, why = vc.reveal_integrity(commit, reveal)
    assert ok, why


def test_versioned_card_verifies_and_ids_recompute():
    commit, reveal = make_versioned([make_decision()])
    ok, why = vc.reveal_integrity(commit, reveal)
    assert ok, why
    assert vc.kalshi_witnessed_ids(reveal) == [reveal["card"]["kalshiDecisions"][0]["decision_id"]]


def test_changing_a_decision_fails():
    # Layer 1: the outer card hash catches the tamper on its own.
    commit, reveal = make_versioned([make_decision()])
    reveal["card"]["kalshiDecisions"][0]["model_probability"] = "0.9990"
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "card changed" in why, why
    # Layer 2: even an attacker who can re-bind the outer hash (controls the nonce) is
    # caught by the kalshi id/root recomputation — the layers fail independently.
    commit["commitHash"] = vc.commit_hash(reveal["card"], reveal["nonce"])
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "kalshi" in why.lower(), why


def test_adding_and_removing_a_decision_fail():
    commit, reveal = make_versioned([make_decision()])
    extra = make_decision(ticker="KXMLBKS-26AUG021335PHIBAL-Y-6")
    with_extra = json.loads(json.dumps(reveal))
    with_extra["card"]["kalshiDecisions"].append(extra)
    ok, why = vc.reveal_integrity(commit, with_extra)
    assert not ok, "an added decision passed verification"
    commit2, reveal2 = make_versioned([make_decision(),
                                       make_decision(ticker="KXMLBKS-26AUG021335PHIBAL-Z-6")])
    reveal2["card"]["kalshiDecisions"].pop()
    ok, why = vc.reveal_integrity(commit2, reveal2)
    assert not ok, "a removed decision passed verification"


def test_commit_card_metadata_binding():
    commit, reveal = make_versioned([make_decision()])
    commit["kalshiDecisionSet"]["count"] = 5
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "differs between commitment and revealed card" in why, why


def test_lying_earliest_fails():
    commit, reveal = make_versioned([make_decision(start="2026-08-02T17:35:00+00:00")])
    reveal["card"]["kalshiDecisionSet"]["earliestEventStart"] = "2026-08-02T23:00:00+00:00"
    # re-bind the commitment so ONLY the earliest lie is under test
    reveal_card = reveal["card"]
    commit["commitHash"] = vc.commit_hash(reveal_card, reveal["nonce"])
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "minimum" in why, why


def test_degraded_set_is_exactly_empty():
    commit, reveal = make_versioned([])
    meta = reveal["card"]["kalshiDecisionSet"]
    meta["status"] = "degraded"
    meta["reasonCodes"] = ["KALSHI_SET_MISSING"]
    meta["root"] = vc.KALSHI_EMPTY_ROOT
    meta["earliestEventStart"] = None
    commit["commitHash"] = vc.commit_hash(reveal["card"], reveal["nonce"])
    commit["kalshiDecisionSet"] = {k: meta[k] for k in
                                   ("schemaVersion", "status", "count", "root", "reasonCodes")}
    ok, why = vc.reveal_integrity(commit, reveal)
    assert ok, why
    assert vc.kalshi_witnessed_ids(reveal) == [], "a degraded set witnessed decisions"
    # degraded with a smuggled decision must fail
    bad = json.loads(json.dumps(reveal))
    bad["card"]["kalshiDecisions"] = [make_decision()]
    commit["commitHash"] = vc.commit_hash(bad["card"], bad["nonce"])
    ok, why = vc.reveal_integrity(commit, bad)
    assert not ok and "exactly empty" in why, why


def test_naive_event_time_fails_an_ok_set():
    commit, reveal = make_versioned([make_decision(start="2026-08-02T13:00:00")])
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "naive" in why, why


def test_missing_metadata_key_fails():
    commit, reveal = make_versioned([make_decision()])
    del reveal["card"]["kalshiDecisionSet"]["reasonCodes"]
    commit["commitHash"] = vc.commit_hash(reveal["card"], reveal["nonce"])
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "metadata keys" in why, why


def test_one_sided_kalshi_keys_fail():
    commit, reveal = make_versioned([make_decision()])
    del commit["kalshiDecisionSet"]
    ok, why = vc.reveal_integrity(commit, reveal)
    assert not ok and "one side only" in why, why


def main():
    check("a legacy card still verifies", test_legacy_card_still_verifies)
    check("a versioned card verifies and ids recompute", test_versioned_card_verifies_and_ids_recompute)
    check("changing a decision fails", test_changing_a_decision_fails)
    check("adding and removing a decision fail", test_adding_and_removing_a_decision_fail)
    check("commitment/card metadata are bound", test_commit_card_metadata_binding)
    check("a lying earliest fails", test_lying_earliest_fails)
    check("a degraded set is exactly empty", test_degraded_set_is_exactly_empty)
    check("a naive event time fails an ok set", test_naive_event_time_fails_an_ok_set)
    check("a missing metadata key fails", test_missing_metadata_key_fails)
    check("one-sided kalshi keys fail", test_one_sided_kalshi_keys_fail)
    if fails:
        print(f"\n{len(fails)} FAILURE(S)")
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
