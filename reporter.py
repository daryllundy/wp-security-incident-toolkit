#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

import click

sys.path.append(str(Path(__file__).resolve().parent / "src"))

from wp_security_toolkit.reporter import REPORT_TYPES, SecurityReport
from wp_security_toolkit.scanner_engine import WordPressSecurityScanner


@click.group()
def cli() -> None:
    """Reporting utilities."""


@cli.command(name="generate")
@click.option(
    "--format", "format_", type=click.Choice(["pdf", "json", "html"]), required=True
)
@click.option(
    "--type",
    "report_type",
    type=click.Choice(sorted(REPORT_TYPES.keys())),
    default="technical",
)
@click.option("--output", "output_path", required=True)
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def generate(format_: str, report_type: str, output_path: str, path_: str) -> None:
    scanner = WordPressSecurityScanner(path_)
    results = scanner.full_scan()
    report = SecurityReport(results, report_type=report_type)
    if format_ == "pdf":
        report.generate_pdf(output_path)
    elif format_ == "json":
        report.generate_json(output_path)
    else:
        report.generate_html(output_path)
    click.echo(f"Report generated at {output_path}")


if __name__ == "__main__":
    cli()
