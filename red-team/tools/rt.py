#!/usr/bin/env python3
"""
rt — unified CLI for the Random-Stuff red-team framework.

    rt.py scenario  --list | --run <stem> [--ir-drill] | --mitre-report
    rt.py derive    --sector <s> | --actor <id> [--build-scenario]
    rt.py recon     --org <o> --domain <d> [--plan [--authorize-active] | --footprint-reduction]
    rt.py navigator

Each subcommand is also runnable standalone (e.g. `python3 tools/scenario.py --list`).
All commands share tools/attack.py for paths, JSON I/O, and ATT&CK-ID handling.
"""

import argparse

import scenario
import derive
import recon
import navigator


def main():
    parser = argparse.ArgumentParser(
        prog="rt",
        description="Unified CLI for the intelligence-led red-team framework.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for module in (scenario, derive, recon, navigator):
        module.register(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
