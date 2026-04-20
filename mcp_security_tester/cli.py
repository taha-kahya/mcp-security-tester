"""
CLI entry point.

Commands:
  mcp-tester scan   --manifest <path>                 # scan a saved manifest file
  mcp-tester scan   --command "uvx mcp-server-git ."  # collect + scan inline (stdio)
  mcp-tester scan   --url http://localhost:8000        # collect + scan inline (SSE)
  mcp-tester collect --command "..."  --name <name>   # save manifest to corpus/
  mcp-tester scan-all                                  # scan every file in corpus/
"""

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from mcp_security_tester.manifest_collector import collector
from mcp_security_tester.reports.json_reporter import to_json, write_json
from mcp_security_tester.reports.models import Report
from mcp_security_tester.static_analyzer.analyzer import analyze_manifest

_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "white",
}


@click.group()
def main() -> None:
    """MCP Security Tester — detect vulnerabilities in MCP servers before deployment."""


@main.command()
@click.option("--manifest", "manifest_path", type=click.Path(exists=True), default=None,
              help="Path to a saved manifest JSON file.")
@click.option("--command", "server_command", default=None,
              help="Shell command to spawn the MCP server (stdio). E.g. 'uvx mcp-server-git .'")
@click.option("--url", "server_url", default=None,
              help="URL of a running MCP server (SSE transport).")
@click.option("--name", "server_name", default=None,
              help="Server name used in the report. Defaults to the manifest filename or command.")
@click.option("--output", "output_path", default=None,
              help="Write JSON report to this file instead of stdout.")
def scan(manifest_path, server_command, server_url, server_name, output_path):
    """Scan an MCP server manifest for security vulnerabilities."""
    if not manifest_path and not server_command and not server_url:
        raise click.UsageError("Provide --manifest, --command, or --url.")

    tools, target = _resolve_tools(manifest_path, server_command, server_url, server_name)

    click.echo(f"Scanning {target} ({len(tools)} tools)...", err=True)
    findings = analyze_manifest(tools)

    report = Report(
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    _print_summary(report)

    if output_path:
        write_json(report, output_path)
        click.echo(f"Report written to {output_path}", err=True)
    else:
        click.echo(to_json(report))

    if report.summary.get("CRITICAL", 0) > 0:
        sys.exit(2)
    if report.summary.get("HIGH", 0) > 0:
        sys.exit(1)


@main.command()
@click.option("--command", "server_command", required=True,
              help="Shell command to spawn the MCP server (stdio).")
@click.option("--name", "server_name", required=True,
              help="Server name for the saved file (e.g. mcp-server-git).")
def collect(server_command, server_name):
    """Fetch a server's tool manifest and save it to corpus/."""
    click.echo(f"Collecting manifest from: {server_command}", err=True)
    command = server_command.split()
    tools = asyncio.run(collector.collect_stdio(command))
    path = collector.save(tools, server_name)
    click.echo(f"Saved {len(tools)} tools to {path}", err=True)


@main.command("scan-all")
@click.option("--output-dir", default=None,
              help="Write individual JSON reports to this directory.")
def scan_all(output_dir):
    """Scan every manifest saved in corpus/."""
    saved = collector.list_saved()
    if not saved:
        click.echo("No manifests in corpus/. Run 'mcp-tester collect' first.", err=True)
        sys.exit(0)

    total_critical = total_high = 0
    for path in saved:
        tools = collector.load(path)
        findings = analyze_manifest(tools)
        report = Report(
            target=path.stem,
            timestamp=datetime.now(timezone.utc).isoformat(),
            findings=findings,
        )
        _print_summary(report)
        total_critical += report.summary.get("CRITICAL", 0)
        total_high += report.summary.get("HIGH", 0)

        if output_dir:
            out = Path(output_dir) / f"{path.stem}.json"
            write_json(report, str(out))

    click.echo(f"\nTotal: {total_critical} CRITICAL, {total_high} HIGH across {len(saved)} servers.", err=True)
    if total_critical > 0:
        sys.exit(2)
    if total_high > 0:
        sys.exit(1)


# ── helpers ──────────────────────────────────────────────────────────────────

def _resolve_tools(manifest_path, server_command, server_url, server_name):
    if manifest_path:
        tools = collector.load(Path(manifest_path))
        target = server_name or Path(manifest_path).stem
    elif server_command:
        command = server_command.split()
        tools = asyncio.run(collector.collect_stdio(command))
        target = server_name or server_command.split()[0]
    else:
        tools = asyncio.run(collector.collect_sse(server_url))
        target = server_name or server_url
    return tools, target


def _print_summary(report: Report) -> None:
    s = report.summary
    click.echo(
        f"\n{report.target}: "
        + click.style(f"{s['CRITICAL']} CRITICAL", fg="red", bold=True) + "  "
        + click.style(f"{s['HIGH']} HIGH", fg="yellow") + "  "
        + click.style(f"{s['MEDIUM']} MEDIUM", fg="cyan") + "  "
        + click.style(f"{s['LOW']} LOW", fg="white"),
        err=True,
    )
    for finding in report.sorted_findings():
        color = _SEVERITY_COLORS[finding.severity]
        click.echo(
            f"  [{click.style(finding.severity, fg=color)}] "
            f"{finding.tool_name} › {finding.field} "
            f"({finding.signal}): {finding.evidence[:80]}",
            err=True,
        )
