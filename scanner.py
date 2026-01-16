#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from colorama import Fore, Style, init

sys.path.append(str(Path(__file__).resolve().parent / "src"))

from wp_security_toolkit.detectors import BackdoorDetector, CryptoMinerDetector
from wp_security_toolkit.integrity import IntegrityChecker
from wp_security_toolkit.reporter import REPORT_TYPES, SecurityReport
from wp_security_toolkit.scanner_engine import WordPressSecurityScanner
from wp_security_toolkit.utils import iter_files

init()


@click.group()
def cli() -> None:
    click.echo(f"{Fore.CYAN}🔒 WordPress Security Incident Toolkit{Style.RESET_ALL}")


@cli.command()
@click.option("--path", "path_", default="/var/www/html", show_default=True)
@click.option("--quick", is_flag=True, help="Scan critical files only.")
@click.option("--rules", "rules_path", default=None, help="Custom YARA rules path.")
@click.option("--verbose", is_flag=True, help="Output detailed findings.")
def scan(path_: str, quick: bool, rules_path: str | None, verbose: bool) -> None:
    """Scan WordPress installation."""
    scanner = WordPressSecurityScanner(path_, rules_path)
    if rules_path:
        results = scanner.scan_with_rules(rules_path)
    elif quick:
        results = scanner.quick_scan()
    else:
        results = scanner.full_scan()

    click.echo(f"{Fore.GREEN}🔍 Scanned: {path_}{Style.RESET_ALL}")
    click.echo(
        f"{Fore.GREEN}✅ Findings: {results['summary']['total_findings']}{Style.RESET_ALL}"
    )
    click.echo(
        f"{Fore.BLUE}📊 Files scanned: {results['summary']['files_scanned']}{Style.RESET_ALL}"
    )
    if verbose:
        click.echo(json.dumps(results, indent=2))


@cli.command(name="crypto-scan")
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def crypto_scan(path_: str) -> None:
    """Detect crypto miner artifacts."""
    detector = CryptoMinerDetector()
    hits = detector.scan_directory(path_)
    click.echo(f"{Fore.YELLOW}⛏️  Crypto miners found: {len(hits)}{Style.RESET_ALL}")
    for hit in hits:
        click.echo(f"- {hit.file_path} ({hit.rule})")


@cli.command(name="backdoor-scan")
@click.option("--path", "path_", default="/var/www/html", show_default=True)
def backdoor_scan(path_: str) -> None:
    """Detect backdoor artifacts."""
    detector = BackdoorDetector()
    hits = detector.scan_directory(path_)
    click.echo(f"{Fore.RED}🧪 Backdoors found: {len(hits)}{Style.RESET_ALL}")
    for hit in hits:
        click.echo(f"- {hit.file_path} ({hit.rule})")


@cli.command(name="integrity-check")
@click.option("--path", "path_", default="/var/www/html", show_default=True)
@click.option("--baseline", "baseline_path", required=True)
@click.option("--create", "create_baseline", is_flag=True, help="Create baseline file.")
def integrity_check(path_: str, baseline_path: str, create_baseline: bool) -> None:
    """Check file integrity against a baseline."""
    checker = IntegrityChecker(baseline_path)
    files = list(iter_files(path_))
    if create_baseline or not Path(baseline_path).exists():
        checker.create_baseline(path_, files)
        click.echo(
            f"{Fore.GREEN}✅ Baseline created at {baseline_path}{Style.RESET_ALL}"
        )
        return
    result = checker.compare(path_, files)
    click.echo(f"{Fore.YELLOW}Added: {len(result.added)}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}Removed: {len(result.removed)}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}Modified: {len(result.modified)}{Style.RESET_ALL}")


@cli.command()
@click.option("--path", "path_", default="/var/www/html", show_default=True)
@click.option(
    "--format", "format_", type=click.Choice(["pdf", "json", "html"]), default="pdf"
)
@click.option(
    "--type",
    "report_type",
    type=click.Choice(sorted(REPORT_TYPES.keys())),
    default="technical",
)
@click.option("--output", "output_path", required=True)
def report(path_: str, format_: str, report_type: str, output_path: str) -> None:
    """Generate security report."""
    scanner = WordPressSecurityScanner(path_)
    results = scanner.full_scan()
    report_obj = SecurityReport(results, report_type=report_type)
    if format_ == "pdf":
        report_obj.generate_pdf(output_path)
    elif format_ == "json":
        report_obj.generate_json(output_path)
    else:
        report_obj.generate_html(output_path)
    click.echo(f"{Fore.GREEN}📄 Report generated at {output_path}{Style.RESET_ALL}")


if __name__ == "__main__":
    cli()
