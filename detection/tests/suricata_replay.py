#!/usr/bin/env python3
"""Replay-test detection/droidjack_suricata.rules against synthetic traffic.

Proof obligation: every rule (SID) in the file fires on traffic carrying the
exact indicator it claims to detect, and no rule fires on benign control
traffic. Rule syntax errors are fatal (--init-errors-fatal).

The positive traffic is synthesised from the indicators documented in
MALWARE_ANALYSIS.md / intel/iocs.csv (C2 domains, URIs, KryoNet token). No
sample traffic is stored or replayed.

Requires: suricata on PATH, scapy. Exit 0 = pass, 1 = fail, 2 = setup error.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap
except ImportError:
    die("scapy is required (pip install scapy)")

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, "..", "droidjack_suricata.rules")
CONFIG = os.environ.get("SURICATA_CONFIG", "/etc/suricata/suricata.yaml")
CLIENT, C2 = "10.0.0.2", "203.0.113.5"


def tcp_session(sport, dport, payloads, dst=C2):
    """A complete client->server TCP session (handshake, data, teardown)."""
    def c2s(**kw):
        return IP(src=CLIENT, dst=dst) / TCP(sport=sport, dport=dport, **kw)

    def s2c(**kw):
        return IP(src=dst, dst=CLIENT) / TCP(sport=dport, dport=sport, **kw)

    pkts, seq, ack = [], 1000, 5000
    pkts.append(c2s(flags="S", seq=seq))
    pkts.append(s2c(flags="SA", seq=ack, ack=seq + 1))
    seq, ack = seq + 1, ack + 1
    pkts.append(c2s(flags="A", seq=seq, ack=ack))
    for p in payloads:
        pkts.append(c2s(flags="PA", seq=seq, ack=ack) / Raw(p))
        seq += len(p)
        pkts.append(s2c(flags="A", seq=ack, ack=seq))
    pkts.append(c2s(flags="FA", seq=seq, ack=ack))
    pkts.append(s2c(flags="FA", seq=ack, ack=seq + 1))
    pkts.append(c2s(flags="A", seq=seq + 1, ack=ack + 1))
    return pkts


def dns_query(name, sport):
    return [IP(src=CLIENT, dst="198.51.100.53") / UDP(sport=sport, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name))]


def malicious():
    return (
        tcp_session(40001, 1337, [b"\x00\x10DJ_GooDbYe:(\x00"])
        + tcp_session(40002, 80, [b"POST /storeReport.php HTTP/1.1\r\n"
                                  b"Host: www.droidjack.net\r\nContent-Length: 2\r\n\r\nab"])
        + tcp_session(40003, 80, [b"GET /Access/DJ HTTP/1.1\r\n"
                                  b"Host: www.droidjack.net\r\n\r\n"])
        + dns_query("droidjack.net", 50001)
        + dns_query("bshades.eu", 50002)
    )


def benign():
    return (
        tcp_session(41001, 1337, [b"\x00\x10hello world\x00"])
        + tcp_session(41002, 80, [b"POST /upload.php HTTP/1.1\r\n"
                                  b"Host: www.example.com\r\nContent-Length: 2\r\n\r\nab"])
        + tcp_session(41003, 80, [b"GET /index.html HTTP/1.1\r\n"
                                  b"Host: www.example.com\r\n\r\n"])
        + dns_query("example.com", 51001)
    )


def rule_sids(path):
    with open(path) as f:
        return {int(m) for m in re.findall(r"\bsid:\s*(\d+)\s*;", f.read())}


def run(pcap, workdir):
    logdir = tempfile.mkdtemp(dir=workdir)
    cmd = ["suricata", "-c", CONFIG, "-S", RULES, "-r", pcap, "-l", logdir,
           "-k", "none", "--init-errors-fatal",
           "--set", "unix-command.enabled=no",
           "--set", "vars.address-groups.HOME_NET=10.0.0.0/8",
           "--set", "vars.address-groups.EXTERNAL_NET=!10.0.0.0/8"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        die("suricata failed (exit %d)" % proc.returncode)
    with open(os.path.join(logdir, "fast.log")) as f:
        return {int(m) for m in re.findall(r"\[1:(\d+):\d+\]", f.read())}


def main():
    if shutil.which("suricata") is None:
        die("suricata is required on PATH")
    expected = rule_sids(RULES)
    if not expected:
        die("no SIDs found in %s" % RULES)
    with tempfile.TemporaryDirectory() as tmp:
        bad = os.path.join(tmp, "malicious.pcap")
        good = os.path.join(tmp, "benign.pcap")
        wrpcap(bad, malicious())
        wrpcap(good, benign())
        fired_bad, fired_good = run(bad, tmp), run(good, tmp)

    ok = True
    missing = sorted(expected - fired_bad)
    if missing:
        print("FAIL: rules did not fire on their indicator traffic: %s" % missing)
        ok = False
    if fired_good:
        print("FAIL: rules fired on benign control traffic: %s" % sorted(fired_good))
        ok = False
    if ok:
        print("PASS: all %d SIDs fire on indicator traffic; 0 alerts on benign control"
              % len(expected))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
