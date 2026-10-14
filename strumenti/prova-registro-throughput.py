#!/usr/bin/env python3
"""Bounded, synthetic collector benchmark; never launches eslogger or touches logs.

The sink counts records without filesystem I/O. CPU refers to this Python
process, excluding eslogger and chain fsync; it is not a live idle-CPU claim.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import registro as R
import registro_daemon as D

ROOT = "/Users/paratia-synthetic/Desktop/folder-test"


def righe_sintetiche(numero):
    """95% unrelated filesystem events, 4% watched accesses, 1% ancestry.

    Unrelated events use only types in the default subscription (write, truncate,
    unlink): close, mount and unmount are no longer subscribed, so they are not
    part of the stream this benchmark stands for.
    Audit/signing/file metadata and harmless synthetic argument/environment fields
    resemble the real event envelope. No machine-specific paths or user data.
    """
    p = {"audit_token": {"pid": 301, "pidversion": 7, "euid": os.getuid(),
                         "ruid": os.getuid(), "rgid": 20, "egid": 20, "auid": os.getuid(), "asid": 1},
         "executable": {"path": "/bin/cat", "path_truncated": False,
                        "stat": {"st_dev": 1, "st_ino": 500, "st_mode": 33261}},
         "ppid": 1, "original_ppid": 1, "group_id": 301, "session_id": 1,
         "is_platform_binary": True, "is_es_client": False, "codesigning_flags": 570491649,
         "signing_id": "com.apple.cat", "team_id": "", "cdhash": "0" * 40,
         "parent_audit_token": {"pid": 1, "pidversion": 1},
         "responsible_audit_token": {"pid": 1, "pidversion": 1}}
    ora = datetime.datetime.now(datetime.timezone.utc).isoformat()
    righe = []
    for i in range(numero):
        caso = i % 100
        tipo = "exec" if caso == 0 else ("open" if caso < 5 else ("write", "truncate", "unlink")[caso % 3])
        percorso = ROOT + "/synthetic.txt" if caso < 5 else "/System/Library/Synthetic/cache.dat"
        file = {"path": percorso, "path_truncated": False,
                "stat": {"st_dev": 1, "st_ino": 123456, "st_mode": 33188, "st_nlink": 1,
                         "st_uid": os.getuid(), "st_gid": 20, "st_size": 512,
                         "st_atimespec": {"tv_sec": 1791936000, "tv_nsec": 0},
                         "st_mtimespec": {"tv_sec": 1791936000, "tv_nsec": 0}}}
        dettaglio = ({"target": p, "args": ["synthetic-argument"], "env": ["SYNTHETIC=1"]}
                     if tipo == "exec" else {"file": file, "fflag": 1} if tipo == "open"
                     else {"target": file})
        msg = {"schema_version": 1, "version": 7, "time": ora,
               "event_type": "ES_EVENT_TYPE_NOTIFY_" + tipo.upper(),
               "seq_num": i + 1, "global_seq_num": i + 1, "process": p,
               "event": {tipo: dettaglio}, "action": {"result_type": 1, "result": {"flags": 1}}}
        righe.append(json.dumps(msg, separators=(",", ":")).encode())
    return righe


def misura(righe, ottimizzato):
    contati = [0]
    def sink(_):
        contati[0] += 1
    osservatore = R.Osservatore([{"id": "synthetic", "origine": ROOT}], sink)
    if not ottimizzato:
        # Emulate the previous collector's per-message account-name lookups.
        # Only display labels are uncached; audit identity logic stays identical.
        osservatore.discendenza.nomi_uid = None
    flusso = D.FlussoEslogger(osservatore) if ottimizzato else None
    ricevi = flusso.ricevi if flusso else lambda r: osservatore.ricevi(json.loads(r))
    cpu_prima, prima = time.process_time(), time.perf_counter()
    for riga in righe:
        ricevi(riga)
    secondi, cpu_secondi = time.perf_counter() - prima, time.process_time() - cpu_prima
    return {"lines_per_second": len(righe) / secondi, "wall_seconds": secondi,
            "cpu_seconds": cpu_secondi, "cpu_microseconds_per_line": cpu_secondi * 1e6 / len(righe),
            "filtered_lines": flusso.filtered_lines if flusso else 0,
            "parsed_lines": flusso.parsed_lines if flusso else len(righe),
            "written_records": contati[0], "dropped_events": osservatore.persi}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lines", type=int, default=50000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--input-rate", type=int, default=30000,
                        help="Synthetic arrival rate for one-core CPU-budget comparison.")
    args = parser.parse_args(argv)
    if not 1000 <= args.lines <= 200000 or not 1 <= args.repeats <= 5 or not 1 <= args.input_rate <= 1000000:
        parser.error("Usa 1000..200000 righe, 1..5 ripetizioni e un rate positivo limitato.")
    righe = righe_sintetiche(args.lines)
    risultati = {"before": [], "after": []}
    for _ in range(args.repeats):
        for nome, ottimizzato in (("before", False), ("after", True)):
            risultati[nome].append(misura(righe, ottimizzato))
    riepilogo = {}
    for nome, prove in risultati.items():
        riepilogo[nome] = {k: round(statistics.median(p[k] for p in prove), 3) for k in prove[0]}
        riepilogo[nome]["cpu_percent_at_input_rate"] = round(
            riepilogo[nome]["cpu_microseconds_per_line"] * args.input_rate / 10000, 2)
    print(json.dumps({"ok": True, "lines": args.lines, "repeats": args.repeats,
                      "mean_line_bytes": round(sum(map(len, righe)) / len(righe), 1),
                      "synthetic_input_lines_per_second": args.input_rate,
                      "cpu_scope": "Python collector only; counter sink, excludes eslogger and fsync",
                      "baseline": "decode every JSON line; repeated account-name lookup without session cache",
                      "live_idle_cpu_verified": False,
                      "speedup": round(riepilogo["after"]["lines_per_second"] / riepilogo["before"]["lines_per_second"], 3),
                      **riepilogo}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
