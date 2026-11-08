#!/usr/bin/env python3
"""Score outbound beaconing in Zeek conn.log and flag hits against the ARTEX IOC list.

The agent plans on the attacker's server; the implant on your host still has to call home
for its next task. That shows up as a regular rhythm to a rare external host. This script
scores each (src, dst, dport) pair on:
  * interval regularity  - low spread of time between connections (jitter-tolerant, uses MAD)
  * size regularity      - similar request sizes
  * persistence          - how much of the window the pair was active
and boosts any pair whose destination is in iocs.csv.

Works on TSV conn.log (zeek default) or JSON conn.log (Security Onion / json-logs).
Accepts plain or .gz files, several at once (e.g. a day of rotated logs).

  python3 beacon_hunt.py /nsm/zeek/logs/2026-11-07/conn.*.log.gz --iocs ../iocs.csv
  python3 beacon_hunt.py conn.log --min-conns 20 --top 50 --csv out.csv
"""
import argparse, csv, gzip, ipaddress, json, statistics, sys
from collections import defaultdict
from pathlib import Path


def open_any(path):
    return gzip.open(path, "rt") if str(path).endswith(".gz") else open(path, "r")


def read_conn(paths):
    for p in paths:
        with open_any(p) as fh:
            fields = None
            for line in fh:
                if not line.strip():
                    continue
                if line.startswith("{"):
                    rec = json.loads(line)
                    yield (float(rec["ts"]), rec["id.orig_h"], rec["id.resp_h"], int(rec["id.resp_p"]),
                           int(rec.get("orig_bytes") or 0), int(rec.get("resp_bytes") or 0))
                    continue
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    continue
                if line.startswith("#") or fields is None:
                    continue
                rec = dict(zip(fields, line.rstrip("\n").split("\t")))
                ob = rec.get("orig_bytes", "-"); rb = rec.get("resp_bytes", "-")
                yield (float(rec["ts"]), rec["id.orig_h"], rec["id.resp_h"], int(rec["id.resp_p"]),
                       int(ob) if ob not in ("-", "") else 0, int(rb) if rb not in ("-", "") else 0)


def is_external(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local or a.is_reserved)


def mad(values):
    m = statistics.median(values)
    return statistics.median([abs(v - m) for v in values]), m


def score_pair(times, sizes, window):
    times.sort()
    deltas = [b - a for a, b in zip(times, times[1:]) if b - a > 0.5]  # drop retransmit-ish dupes
    if len(deltas) < 5:
        return None
    d_mad, d_med = mad(deltas)
    s_mad, s_med = mad(sizes)
    interval = max(0.0, 1 - (d_mad / d_med)) if d_med else 0.0        # 1 = metronome
    size = max(0.0, 1 - (s_mad / s_med)) if s_med else 1.0            # empty keepalives are regular too
    persistence = min(1.0, (times[-1] - times[0]) / window) if window else 0.0
    total = round(0.5 * interval + 0.2 * size + 0.3 * persistence, 3)
    return total, round(interval, 3), round(size, 3), round(persistence, 3), round(d_med, 1)


def load_iocs(path):
    iocs = {}
    if path and Path(path).exists():
        for r in csv.DictReader(open(path, newline="")):
            if r["type"] == "ipv4":
                iocs[r["indicator"]] = f'{r["campaign"]} / {r["category"]}'
    return iocs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--iocs", default=str(Path(__file__).resolve().parent.parent / "iocs.csv"))
    ap.add_argument("--min-conns", type=int, default=12)
    ap.add_argument("--max-fanin", type=int, default=5,
                    help="ignore destinations contacted by more internal hosts than this (CDNs, update servers)")
    ap.add_argument("--threshold", type=float, default=0.75)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--csv")
    a = ap.parse_args()

    iocs = load_iocs(a.iocs)
    pairs = defaultdict(lambda: ([], []))
    fanin = defaultdict(set)
    tmin, tmax = float("inf"), 0.0
    ioc_hits = defaultdict(int)

    for ts, src, dst, dport, ob, rb in read_conn(a.logs):
        tmin, tmax = min(tmin, ts), max(tmax, ts)
        if dst in iocs or src in iocs:
            ioc_hits[(src, dst, dport)] += 1
        if not is_external(dst) or is_external(src):
            continue
        t, s = pairs[(src, dst, dport)]
        t.append(ts); s.append(ob)
        fanin[dst].add(src)

    window = tmax - tmin if tmax > tmin else 0
    results = []
    for (src, dst, dport), (times, sizes) in pairs.items():
        ioc = iocs.get(dst, "")
        if len(times) < a.min_conns and not ioc:
            continue
        if len(fanin[dst]) > a.max_fanin and not ioc:
            continue
        sc = score_pair(times, sizes, window) if len(times) >= 6 else None
        if sc is None and not ioc:
            continue
        total, iv, sz, pe, med = sc if sc else (0, 0, 0, 0, 0)
        if ioc:
            total = round(min(1.0, total + 0.5), 3)
        if total >= a.threshold or ioc:
            results.append(dict(score=total, src=src, dst=dst, dport=dport, conns=len(times),
                                median_interval_s=med, interval=iv, size=sz, persistence=pe,
                                fanin=len(fanin[dst]), ioc=ioc))

    results.sort(key=lambda r: (-bool(r["ioc"]), -r["score"]))
    print(f"window: {window/3600:.1f}h  pairs scored: {len(pairs)}  flagged: {len(results)}  "
          f"IOC flows (any direction): {sum(ioc_hits.values())}")
    if ioc_hits:
        print("\n!! Traffic to/from published ARTEX/CyberStrikeAI infrastructure:")
        for (s, d, p), n in sorted(ioc_hits.items(), key=lambda x: -x[1]):
            print(f"   {s} -> {d}:{p}  conns={n}  [{iocs.get(d) or iocs.get(s)}]")
    print(f"\n{'score':>5}  {'src':<15} {'dst':<15} {'port':>5} {'conns':>5} {'every':>7}  {'ivl':>4} {'size':>4} {'pers':>4}  ioc")
    for r in results[:a.top]:
        print(f"{r['score']:>5}  {r['src']:<15} {r['dst']:<15} {r['dport']:>5} {r['conns']:>5} "
              f"{r['median_interval_s']:>6}s  {r['interval']:>4} {r['size']:>4} {r['persistence']:>4}  {r['ioc']}")
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(results[0].keys()) if results else ["score"])
            w.writeheader(); w.writerows(results)
        print(f"\nwrote {a.csv}")
    return 1 if (ioc_hits or results) else 0


if __name__ == "__main__":
    sys.exit(main())
