import yaml
import json
import subprocess
from datetime import datetime, timezone
import argparse

def load_plan(path):
    with open(path) as f:
        return yaml.safe_load(f)

def run_scan(targets, proto, ports):
    cmd = ['nmap',]
    if proto == 'tcp': cmd += ['-sS']
    if proto == 'udp': cmd += ['-sU']
    cmd += ['--min-rate', '3000', '-p', ','.join(map(str, ports))]
    cmd += targets
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout

def parse_nmap(output):
    open_ports = []
    for line in output.splitlines():
        if '/open' in line:
            parts = line.split()
            port = int(parts[0].split('/')[0])
            open_ports.append(port)
    return open_ports

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='/data/expected_rules.yml')
    args = parser.parse_args()

    plan = load_plan(args.config)
    mismatches = []
    logs = []
    for rule in plan['rules']:
        srcs = rule['src_cidrs']
        dsts = rule['dst_cidrs']
        proto = rule['protocol']
        ports = rule['ports']
        # Flatten
        for dst in dsts:
            output = run_scan([dst], proto, ports)
            found = parse_nmap(output)
            expected = set(ports)
            got = set(found)
            open_mismatch = list(got - expected)
            closed_mismatch = list(expected - got)
            ts = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            log = {
                'ts_utc': ts,
                'target_ip': dst,
                'scan_type': proto,
                'expected_open': len(expected),
                'expected_closed': 65535 - len(expected),
                'open_mismatches': open_mismatch,
                'closed_mismatches': closed_mismatch
            }
            logs.append(log)
            # Print colored summary
            if not open_mismatch and not closed_mismatch:
                print(f"\x1b[32m[OK]\x1b[32m[OK]\x1b[0m {dst} {proto} ports match expected")
            else:
                print(f"\x1b[31m[MISMATCH]\x1b[31m[MISMATCH]\x1b[0m {dst} {proto}")
            mismatches.extend(open_mismatch + closed_mismatch)
    # Write JSON log
    import os
    os.makedirs('/var/log/portsleuth', exist_ok=True)
    with open('/var/log/portsleuth/probe.json', 'a') as f:
        for entry in logs:
            f.write(json.dumps(entry) + '\n')
    exit(2 if mismatches else 0)