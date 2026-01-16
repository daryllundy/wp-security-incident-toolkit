#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

sys.path.append(str(Path(__file__).resolve().parent / "src"))

from wp_security_toolkit.incident_response import IncidentResponder


@click.group()
def cli() -> None:
    """Incident response workflows."""


@cli.command(name="create-report")
@click.option("--site", "site", required=True)
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def create_report(site: str, path_: str) -> None:
    responder = IncidentResponder(path_)
    result = responder.create_report(site)
    click.echo(json.dumps(result, indent=2))


@cli.command()
@click.option("--malware-list", "malware_list", required=True)
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def quarantine(malware_list: str, path_: str) -> None:
    responder = IncidentResponder(path_)
    records = responder.quarantine_files(malware_list)
    click.echo(json.dumps(records, indent=2))


@cli.command(name="recovery-plan")
@click.option("--incident-id", "incident_id", required=True)
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def recovery_plan(incident_id: str, path_: str) -> None:
    responder = IncidentResponder(path_)
    plan = responder.recovery_plan(incident_id)
    click.echo(json.dumps(plan, indent=2))


@cli.command()
@click.option("--start-date", "start_date", required=True)
@click.option("--end-date", "end_date", required=True)
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def timeline(start_date: str, end_date: str, path_: str) -> None:
    responder = IncidentResponder(path_)
    events = responder.timeline(start_date, end_date)
    click.echo(json.dumps([event.__dict__ for event in events], indent=2))


if __name__ == "__main__":
    cli()
