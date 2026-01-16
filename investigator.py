#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

sys.path.append(str(Path(__file__).resolve().parent / "src"))

from wp_security_toolkit.investigator import Investigator


@click.group()
def cli() -> None:
    """Investigation tools."""


@cli.command(name="analyze")
@click.option("--file", "file_path", required=True)
def analyze(file_path: str) -> None:
    investigator = Investigator()
    result = investigator.analyze_file(file_path)
    click.echo(json.dumps(result, indent=2))


@cli.command()
@click.option("--incident-id", "incident_id", required=True)
@click.option("--start-date", "start_date", required=False, default="")
@click.option("--end-date", "end_date", required=False, default="")
@click.option("--incident-dir", "incident_dir", default=".incidents")
def timeline(
    incident_id: str, start_date: str, end_date: str, incident_dir: str
) -> None:
    investigator = Investigator()
    events = investigator.timeline(incident_dir, start_date, end_date)
    click.echo(json.dumps(events, indent=2))


@cli.command()
@click.option(
    "--output-format", "output_format", type=click.Choice(["json"]), default="json"
)
def forensics(output_format: str) -> None:
    click.echo(json.dumps({"status": "ready", "format": output_format}, indent=2))


if __name__ == "__main__":
    cli()
