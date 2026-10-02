"""
`rt simulate` — safe, local adversary-simulation engine for AUTHORIZED environments.

Executes benign actions that *mimic the form* of attacker TTPs so a blue team can
verify their detections fire. All actions are local, reversible, and clearly
labeled:
- Write a decoy file with a known-bad filename pattern.
- Spawn a benign child process from a parent to simulate Office→shell.
- Create a scheduled task that runs a harmless command (Windows only).
- Touch a canary registry key/path.
- Emit synthetic DNS queries to test network detection rules.

NEVER run this on a system you do not own or are not explicitly authorized to test.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import attack


AUTHORIZATION_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  AUTHORIZED PURPLE-TEAM SIMULATION ONLY                              ║
║                                                                      ║
║  • Run only on systems you own or have written authorization to test.║
║  • All actions are benign and reversible.                            ║
║  • No real malicious payload, C2, or data theft is performed.        ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def _require_authorization(args):
    if not args.i_authorize_this_is_my_system:
        print("ERROR: pass --i-authorize-this-is-my-system to confirm scope.")
        sys.exit(2)


def _stamp():
    return datetime.now().isoformat()


def simulate_drop_malware_decoy(args):
    """Drop a benign file with a name/location that mimics malware staging."""
    target_dir = Path(args.dir or tempfile.gettempdir()) / "redteam_sim"
    target_dir.mkdir(exist_ok=True)
    decoy = target_dir / f"payload_{_stamp().replace(':', '-')}.exe"
    decoy.write_text("This is a benign decoy file for authorized detection testing.", encoding="ascii")
    print(f"[T1204] Dropped decoy: {decoy}")
    return {"technique": "T1204", "path": str(decoy), "timestamp": _stamp()}


def simulate_office_spawns_shell(args):
    """Simulate Office→interpreter execution by spawning a benign child process."""
    interpreter = args.interpreter or ("cmd.exe" if platform.system() == "Windows" else "sh")
    marker = f"redteam-simulation-office-spawn-{int(time.time())}"
    if platform.system() == "Windows":
        cmd = [interpreter, "/c", f"echo {marker}"]
    else:
        cmd = [interpreter, "-c", f"echo {marker}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    print(f"[T1204.002] Spawned {interpreter}; stdout: {proc.stdout.strip()}")
    return {"technique": "T1204.002", "parent": "simulated-office", "child": interpreter, "marker": marker}


def simulate_scheduled_task(args):
    """Create a harmless scheduled task (Windows) or cron entry simulation."""
    if platform.system() == "Windows":
        task_name = args.name or f"RedTeamSim_{int(time.time())}"
        cmd = f"schtasks /create /tn {task_name} /tr \"cmd.exe /c echo redteam-sim-task\" /sc once /st 23:59 /f"
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        print(f"[T1053.005] Scheduled task created: {task_name}")
        print(f"   stdout: {proc.stdout.strip()}")
        print(f"   stderr: {proc.stderr.strip()}")
        return {"technique": "T1053.005", "task_name": task_name, "platform": "windows"}
    else:
        # On non-Windows just print what would be done.
        print("[T1053.005] Simulated cron entry:")
        print("   * * * * * echo 'redteam-sim-task'")
        return {"technique": "T1053.005", "platform": "non-windows", "note": "cron not created"}


def simulate_dns_queries(args):
    """Emit DNS lookups for decoy C2 domains to test network rules."""
    domains = args.domains.split(",") if args.domains else ["sim-c2.example"]
    results = []
    for domain in domains:
        try:
            # gethostbyname is benign; it just performs a DNS lookup.
            import socket
            socket.gethostbyname(domain)
        except socket.gaierror:
            pass
        print(f"[T1071.004] DNS lookup emitted: {domain}")
        results.append(domain)
        time.sleep(0.2)
    return {"technique": "T1071.004", "domains": results}


def simulate_registry_run_key(args):
    """Write a benign Run-key style persistence marker."""
    if platform.system() != "Windows":
        print("[T1547.001] Skipped: registry simulation requires Windows.")
        return {"technique": "T1547.001", "platform": "non-windows", "skipped": True}
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = args.name or f"RedTeamSim_{int(time.time())}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, "cmd.exe /c echo redteam-sim-runkey")
        print(f"[T1547.001] Run key written: HKCU\\{key_path}\\{value_name}")
        return {"technique": "T1547.001", "value_name": value_name}
    except OSError as e:
        print(f"[T1547.001] Could not write registry: {e}")
        return {"technique": "T1547.001", "error": str(e)}


def _emit_log(actions, output_path):
    log = {"authorization": "authorized-purple-team-simulation", "actions": actions}
    print("\nSimulation log:")
    print(json.dumps(log, indent=2))
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
        print(f"\n✅ Log written: {path}")


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    p.add_argument(
        "--i-authorize-this-is-my-system",
        action="store_true",
        required=True,
        help="Confirm you own or are authorized to test this system",
    )
    p.add_argument("-o", "--output", help="Write simulation log to this path")
    sub = p.add_subparsers(dest="action", required=True)

    def _add_output(sp):
        sp.add_argument("-o", "--output", help="Write simulation log to this path")
        return sp

    drop = _add_output(sub.add_parser("drop-decoy", help="Drop a benign file with a malware-like name"))
    drop.add_argument("--dir", help="Directory to drop decoy into")

    spawn = _add_output(sub.add_parser("office-spawn", help="Spawn a benign interpreter to simulate Office→shell"))
    spawn.add_argument("--interpreter", help="Interpreter executable to spawn")

    task = _add_output(sub.add_parser("scheduled-task", help="Create a harmless scheduled task"))
    task.add_argument("--name", help="Task name")

    dns = _add_output(sub.add_parser("dns-queries", help="Emit DNS lookups for decoy C2 domains"))
    dns.add_argument("--domains", help="Comma-separated decoy domains")

    reg = _add_output(sub.add_parser("registry-run", help="Write a benign Run-key marker (Windows)"))
    reg.add_argument("--name", help="Registry value name")

    chain = _add_output(sub.add_parser("chain", help="Run a short chain of simulations"))
    chain.add_argument("--delay", type=float, default=1.0, help="Seconds between actions")
    chain.add_argument("--dir", help="Directory to drop decoy into")
    chain.add_argument("--interpreter", help="Interpreter executable to spawn")
    chain.add_argument("--domains", help="Comma-separated decoy domains")


def handle(args):
    print(AUTHORIZATION_BANNER)
    _require_authorization(args)
    actions = []

    if args.action == "drop-decoy":
        actions.append(simulate_drop_malware_decoy(args))
    elif args.action == "office-spawn":
        actions.append(simulate_office_spawns_shell(args))
    elif args.action == "scheduled-task":
        actions.append(simulate_scheduled_task(args))
    elif args.action == "dns-queries":
        actions.append(simulate_dns_queries(args))
    elif args.action == "registry-run":
        actions.append(simulate_registry_run_key(args))
    elif args.action == "chain":
        print(f"\nRunning simulation chain with {args.delay}s delay...\n")
        actions.append(simulate_drop_malware_decoy(args))
        time.sleep(args.delay)
        actions.append(simulate_office_spawns_shell(args))
        time.sleep(args.delay)
        actions.append(simulate_dns_queries(args))
        time.sleep(args.delay)
        actions.append(simulate_scheduled_task(args))

    _emit_log(actions, args.output)


def register(subparsers):
    p = subparsers.add_parser(
        "simulate",
        help="Run safe, local adversary-simulation actions for authorized testing",
    )
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Safe adversary simulation engine")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
