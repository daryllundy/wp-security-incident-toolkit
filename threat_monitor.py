#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

sys.path.append(str(Path(__file__).resolve().parent / "src"))

from wp_security_toolkit.threat_monitor import ThreatMonitor


@click.command()
@click.option("--daemon", is_flag=True, help="Run continuous monitoring.")
@click.option("--interval", default=300, show_default=True)
@click.option("--path", "path_", default="/var/www/html", show_default=True)
@click.option("--feed", "feed_path", default=None)
def cli(daemon: bool, interval: int, path_: str, feed_path: str | None) -> None:
    monitor = ThreatMonitor(path_, feed_path)
    if daemon:
        monitor.run_daemon(interval)
    else:
        result = monitor.run_once()
        click.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    cli()
