#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

sys.path.append(str(Path(__file__).resolve().parent / "src"))

from wp_security_toolkit.system_audit import SystemAuditor


@click.command()
@click.option("--comprehensive", is_flag=True, help="Run full system audit.")
@click.option("--apply-recommendations", is_flag=True)
@click.option("--path", "path_", default="/", show_default=True)
def cli(comprehensive: bool, apply_recommendations: bool, path_: str) -> None:
    auditor = SystemAuditor(path_)
    if apply_recommendations:
        click.echo(json.dumps(auditor.apply_recommendations(), indent=2))
        return
    results = auditor.audit()
    click.echo(json.dumps(results, indent=2))


if __name__ == "__main__":
    cli()
