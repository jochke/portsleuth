#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import yaml
import nmap
from colorama import Fore, Style, init

LOG_PATH = '/var/log/portsleuth/probe.json'
DEFAULT_SCAN_OPTS = "-sS -sU --min-rate 3000"
MAX_PORT = 65535

def load_plan(path):
    with open(path) as f:
        return yaml.safe_load(f)

def ensure_logfile(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def ts_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'

def run_scan(target, scan_args):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=scan_args)
    hosts = nm.all_hosts()
    return hosts, nm

def compare(rule, hosts, nm):
    """Return a dict with:
       - expected_open: set of ports the plan said should be open
       - actual_open:   set of ports nmap actually saw open
       - open_mismatches:       expected_open - actual_open
       - closed_mismatches:     actual_open - expected_open
    """
    proto = rule['protocol']
    expected = set(rule['ports'])
    actual_open = set()

    # If nmap returned no info for this protocol, treat all as closed
    for host in hosts:
        try:
            states = nm[host][proto]
        except KeyError:
            states = {}
        # collect all ports that nmap says "open"
        actual_open |= {p for p, s in states.items() if s['state'] == 'open'}

    return {
        'expected_open':      expected,
        'actual_open':        actual_open,
        'open_mismatches':    sorted(expected - actual_open),
        'closed_mismatches':  sorted(actual_open - expected),
    }

def log_record(rec):
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(rec) + '\n')

def colorised_print(ok, msg):
    if ok:
        print(Fore.GREEN + msg + Style.RESET_ALL)
    else:
        print(Fore.RED + msg + Style.RESET_ALL)

def main():
    init()  # Initialize Colorama

    p = argparse.ArgumentParser(
        description="PortSleuth Probe",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument(
        '--plan', '-p',
        required=True,
        help="Path to YAML test-plan file (src_cidr, dst_cidr, protocol, ports)"
    )
    p.add_argument(
        '--targets', '-t',
        required=True,
        help="Comma-separated list of one or more target IPs or CIDRs"
    )
    p.add_argument(
        '--scan-opts', '-s',
        default=DEFAULT_SCAN_OPTS,
        help="Extra nmap arguments (default: %(default)s)"
    )

    args = p.parse_args()

    plan = load_plan(args.plan)
    ensure_logfile(LOG_PATH)

    # Build a flat list of targets from the --targets flag
    target_list = [t.strip() for t in args.targets.split(',') if t.strip()]
    if not target_list:
        print("Error: --targets must be a non-empty, comma-separated list", file=sys.stderr)
        sys.exit(1)

    overall_ok = True

    for rule in plan:
        dst = rule.get('dst_cidr')
        if dst not in target_list:
            continue

        proto = rule['protocol'].lower()
        ts = ts_utc()

        hosts, nm = run_scan(dst, args.scan_opts)
        cmp = compare(rule, hosts, nm)

        expected_set = cmp['expected_open']
        actual_set   = cmp['actual_open']
        open_mis     = cmp['open_mismatches']
        closed_mis   = cmp['closed_mismatches']
        successful   = sorted(expected_set & actual_set)

        # Build the JSON record
        record = {
            'ts_utc':            ts,
            'target_ip':         dst,
            'scan_type':         proto,
            'expected_open':     sorted(expected_set),
            'successful_open':   successful,
            'open_mismatches':   open_mis,
            'closed_mismatches': closed_mis,
        }
        log_record(record)

        ok = not open_mis and not closed_mis
        overall_ok &= ok

        header = f"[{'PASS' if ok else 'FAIL'}] {ts} → {dst} ({proto.upper()})"
        colorised_print(ok, header)

        # Always print what was expected vs what was actually open
        print(f"  • Expected open ports: {sorted(expected_set)}")
        print(f"  • Successfully seen open: {successful}")

        if open_mis:
            print(f"  • Expected but not seen open: {open_mis}")
        if closed_mis:
            print(f"  • Unexpected open ports: {closed_mis}")

    sys.exit(0 if overall_ok else 2)

if __name__ == '__main__':
    main()
