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
    proto = rule['protocol']
    expected = set(rule['ports'])
    mismatches = {
        'open_mismatches': [],
        'closed_mismatches': []
    }
    for host in hosts:
        try:
            states = nm[host][proto]
        except KeyError:
            # If nmap returned no info for this protocol, treat all as closed
            states = {}
        actual_open = {p for p, s in states.items() if s['state'] == 'open'}
        mismatches['open_mismatches'] = sorted(expected - actual_open)
        mismatches['closed_mismatches'] = sorted(actual_open - expected)
    return mismatches

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
        help="Comma-separated list of one or more target IPs or CIDRs (e.g. 203.0.113.10,203.0.113.20)"
    )
    p.add_argument(
        '--scan-opts', '-s',
        default=DEFAULT_SCAN_OPTS,
        help="Extra nmap arguments (default: %(default)s)"
    )

    args = p.parse_args()

    # Load the YAML plan (but note: in this example we ignore the plan's src_cidr,
    # since nmap is running from whatever machine you're on; we just scan dst_cidr)
    plan = load_plan(args.plan)
    ensure_logfile(LOG_PATH)

    # Build a flat list of targets from the --targets flag
    target_list = [t.strip() for t in args.targets.split(',') if t.strip()]
    if not target_list:
        print("Error: --targets must be a non-empty, comma-separated list", file=sys.stderr)
        sys.exit(1)

    overall_ok = True

    for rule in plan:
        # The rule’s dst_cidr must be one of the IPs in --targets
        dst = rule.get('dst_cidr')
        if dst not in target_list:
            # If the rule’s dst_cidr isn't in our --targets list, skip it.
            continue

        proto = rule['protocol'].lower()
        ts = ts_utc()

        # Run nmap against exactly that one host/CIDR
        hosts, nm = run_scan(dst, args.scan_opts)
        mm = compare(rule, hosts, nm)

        record = {
            'ts_utc':           ts,
            'target_ip':        dst,
            'scan_type':        proto,
            'expected_open':    len(rule['ports']),
            'expected_closed':  MAX_PORT - len(rule['ports']),
            'open_mismatches':  mm['open_mismatches'],
            'closed_mismatches': mm['closed_mismatches'],
        }
        log_record(record)

        ok = not mm['open_mismatches'] and not mm['closed_mismatches']
        overall_ok &= ok

        header = f"[{'PASS' if ok else 'FAIL'}] {ts} → {dst} ({proto.upper()})"
        colorised_print(ok, header)

        if not ok:
            if mm['open_mismatches']:
                print(f"  • Expected open but not seen: {mm['open_mismatches']}")
            if mm['closed_mismatches']:
                print(f"  • Unexpected open ports: {mm['closed_mismatches']}")

    sys.exit(0 if overall_ok else 2)

if __name__ == '__main__':
    main()
