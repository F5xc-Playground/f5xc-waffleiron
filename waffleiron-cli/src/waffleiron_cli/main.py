"""WaffleIron CLI — convert, analyze, validate, push, and check XC status."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from waffleiron import (
    DecisionSet,
    ReportFormat,
    analyze as analyze_policy,
    generate_report,
    parse,
    translate,
    validate_outputs,
)
from waffleiron.analysis import AnalysisResult
from waffleiron.decisions import (
    AlarmOnlyAction,
    BotDecision,
    BotDecisionAction,
    SignatureDecision,
    ViolationAction,
    ViolationDecision,
)

app = typer.Typer(
    name="waffleiron",
    help="Convert BIG-IP AWAF policies to F5 XC WAF configurations",
)
console = Console()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIG_ACTION_MAP = {
    "exclude": AlarmOnlyAction.EXCLUDE,
    "enforce": AlarmOnlyAction.ENFORCE,
}

_VIOL_ACTION_MAP = {
    "disable": ViolationAction.DISABLE,
    "enforce": ViolationAction.ENFORCE,
}


def _check_file_exists(path: Path) -> None:
    """Abort with a clear error if *path* does not exist."""
    if not path.exists():
        console.print(f"[red]Error:[/red] file not found: {path}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# convert
# ---------------------------------------------------------------------------


@app.command()
def convert(
    policy_file: Path = typer.Argument(..., help="Path to AWAF policy file (XML or JSON)"),
    namespace: str = typer.Option(..., help="Target XC namespace"),
    output: Path = typer.Option(..., help="Output directory"),
    alarm_only_signatures: str = typer.Option(
        "defer", help="Bulk action for alarm-only sigs: exclude|enforce|defer"
    ),
    alarm_only_violations: str = typer.Option(
        "defer", help="Bulk action for alarm-only violations: disable|enforce|defer"
    ),
    decisions: Optional[Path] = typer.Option(None, help="Path to decisions YAML file"),
) -> None:
    """Parse an AWAF policy and produce XC WAF configuration files."""
    valid_sig_actions = {"exclude", "enforce", "defer"}
    valid_viol_actions = {"disable", "enforce", "defer"}
    if alarm_only_signatures not in valid_sig_actions:
        console.print(f"[red]Error:[/red] invalid --alarm-only-signatures value '{alarm_only_signatures}'. Must be one of: {', '.join(valid_sig_actions)}")
        raise typer.Exit(code=1)
    if alarm_only_violations not in valid_viol_actions:
        console.print(f"[red]Error:[/red] invalid --alarm-only-violations value '{alarm_only_violations}'. Must be one of: {', '.join(valid_viol_actions)}")
        raise typer.Exit(code=1)

    _check_file_exists(policy_file)

    policy = parse(policy_file)
    analysis = analyze_policy(policy)

    # Build or load decisions
    if decisions is not None:
        _check_file_exists(decisions)
        decision_set = DecisionSet.load_yaml(decisions)
    else:
        decision_set = _build_decisions_from_analysis(analysis)

    if decisions is not None and (alarm_only_signatures != "defer" or alarm_only_violations != "defer"):
        console.print("[yellow]Warning:[/yellow] bulk overrides will be applied on top of the loaded decisions file.")

    # Apply bulk overrides (only when not "defer")
    if alarm_only_signatures in _SIG_ACTION_MAP:
        decision_set.bulk_set_signatures(_SIG_ACTION_MAP[alarm_only_signatures])
    if alarm_only_violations in _VIOL_ACTION_MAP:
        decision_set.bulk_set_violations(_VIOL_ACTION_MAP[alarm_only_violations])

    # Translate
    result = translate(policy, decision_set, namespace)

    from waffleiron.manifest import build_manifest

    # Write outputs in backup-tool-compatible layout
    output.mkdir(parents=True, exist_ok=True)

    for rel_path, obj in result.output_files().items():
        file_path = output / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(json.dumps(obj, indent=2))

    # Manifest
    manifest = build_manifest(result=result, namespace=namespace, source_policy=policy.name)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # Gap report (Markdown)
    md_report = generate_report(
        analysis, decision_set, ReportFormat.MARKDOWN, policy_name=policy.name
    )
    (output / "gap_report.md").write_text(md_report)

    # Decisions YAML
    decision_set.save_yaml(output / "decisions.yaml")

    console.print(f"[green]Conversion complete.[/green] Output written to {output}")


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    policy_file: Path = typer.Argument(..., help="Path to AWAF policy file (XML or JSON)"),
    output: Path = typer.Option(..., help="Output directory"),
) -> None:
    """Analyze an AWAF policy and produce gap reports and a decisions template."""
    _check_file_exists(policy_file)

    policy = parse(policy_file)
    analysis = analyze_policy(policy)

    decision_set = _build_decisions_from_analysis(analysis)

    output.mkdir(parents=True, exist_ok=True)

    # Markdown report
    md_report = generate_report(
        analysis, decision_set, ReportFormat.MARKDOWN, policy_name=policy.name
    )
    (output / "gap_report.md").write_text(md_report)

    # JSON report
    json_report = generate_report(
        analysis, decision_set, ReportFormat.JSON, policy_name=policy.name
    )
    (output / "gap_report.json").write_text(json_report)

    # Decisions YAML
    decision_set.save_yaml(output / "decisions.yaml")

    console.print(f"[green]Analysis complete.[/green] Output written to {output}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

_VALIDATE_KIND_MAP: dict[str, str] = {
    "app-firewall": "app_firewall",
    "waf-exclusion-policy": "waf_exclusion_policy",
}


@app.command()
def validate(
    output_dir: Path = typer.Argument(..., help="Directory containing XC JSON output files"),
) -> None:
    """Validate XC output JSON files against API constraints."""
    if not output_dir.is_dir():
        console.print(f"[red]Error:[/red] not a directory: {output_dir}")
        raise typer.Exit(code=1)

    all_valid = True
    checked = 0

    for kind_dir, object_type in _VALIDATE_KIND_MAP.items():
        kind_path = output_dir / kind_dir
        if not kind_path.is_dir():
            continue
        for filepath in sorted(kind_path.glob("*.json")):
            filename = f"{kind_dir}/{filepath.name}"
            obj = json.loads(filepath.read_text())
            result = validate_outputs(obj, object_type)
            checked += 1

            if result.errors:
                all_valid = False
                table = Table(title=f"Validation errors: {filename}")
                table.add_column("Path")
                table.add_column("Message")
                for err in result.errors:
                    table.add_row(err.path, err.message)
                console.print(table)

            if result.warnings:
                table = Table(title=f"Validation warnings: {filename}")
                table.add_column("Path")
                table.add_column("Message")
                for warn in result.warnings:
                    table.add_row(warn.path, warn.message)
                console.print(table)

            if result.is_valid:
                console.print(f"[green]{filename}:[/green] valid")

    if checked == 0:
        console.print("[yellow]No validatable JSON files found in the directory.[/yellow]")
        raise typer.Exit(code=1)

    if all_valid:
        console.print("[green]All files passed validation.[/green]")
    else:
        console.print("[red]Validation failed.[/red]")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# push (stub)
# ---------------------------------------------------------------------------


def _resolve_push_config(
    tenant_url: str | None,
    api_token: str | None,
    p12_path: Path | None,
    p12_password: str | None,
) -> "XCConfig | None":
    """Build XCConfig from explicit args or fall back to env-var resolution."""
    from waffleiron.xc_client import XCConfig

    if tenant_url and api_token:
        return XCConfig(tenant_url=tenant_url, api_token=api_token, auth_method="token")
    if tenant_url and p12_path:
        return XCConfig(
            tenant_url=tenant_url,
            auth_method="p12",
            p12_path=str(p12_path),
            p12_password=p12_password,
        )
    return XCConfig.from_env()


_PUSH_KIND_MAP: dict[str, str] = {
    "app-firewall": "app_firewalls",
    "waf-exclusion-policy": "waf_exclusion_policys",
    "service-policy": "service_policys",
}


@app.command()
def push(
    output_dir: Path = typer.Argument(..., help="Directory containing XC JSON output files"),
    namespace: Optional[str] = typer.Option(None, help="Override namespace in pushed objects"),
    shared: bool = typer.Option(False, help="Push to shared namespace"),
    tenant_url: Optional[str] = typer.Option(None, envvar="F5XC_TENANT_URL"),
    api_token: Optional[str] = typer.Option(None, envvar="F5XC_API_TOKEN"),
    p12_path: Optional[Path] = typer.Option(None, envvar="F5XC_P12_PATH"),
    p12_password: Optional[str] = typer.Option(None, envvar="F5XC_P12_PASSWORD"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be pushed without pushing"),
) -> None:
    """Push XC configuration objects to an F5 XC tenant."""
    if not output_dir.is_dir():
        console.print(f"[red]Error:[/red] not a directory: {output_dir}")
        raise typer.Exit(code=1)

    if shared:
        namespace = "shared"

    xc_config = _resolve_push_config(tenant_url, api_token, p12_path, p12_password)
    if xc_config is None:
        console.print("[red]Error:[/red] No XC credentials. Set F5XC_TENANT_URL + F5XC_API_TOKEN or use --tenant-url/--api-token.")
        raise typer.Exit(code=1)

    from waffleiron.xc_client import XCClient

    client = XCClient(xc_config)

    pushed = 0
    for kind_dir, resource in _PUSH_KIND_MAP.items():
        kind_path = output_dir / kind_dir
        if not kind_path.is_dir():
            continue
        for filepath in sorted(kind_path.glob("*.json")):
            obj = json.loads(filepath.read_text())

            # Namespace override
            if namespace:
                obj.setdefault("metadata", {})["namespace"] = namespace

            obj_ns = obj.get("metadata", {}).get("namespace", "default")
            obj_name = obj.get("metadata", {}).get("name", "unknown")
            display_name = f"{kind_dir}/{filepath.name}"

            if dry_run:
                console.print(f"  [dim]would push[/dim] {display_name} → {obj_ns}/{obj_name}")
                pushed += 1
                continue

            try:
                client.create_object(resource, obj_ns, obj)
                console.print(f"  [green]✓[/green] {display_name} → {obj_ns}/{obj_name}")
                pushed += 1
            except Exception as e:
                console.print(f"  [red]✗[/red] {display_name} → {obj_ns}/{obj_name}: {e}")

    if pushed == 0:
        console.print("[yellow]No pushable JSON files found in the directory.[/yellow]")
        raise typer.Exit(code=1)

    if dry_run:
        console.print(f"\n[dim]Dry run complete. {pushed} object(s) would be pushed.[/dim]")
    else:
        console.print(f"\n[green]Push complete.[/green] {pushed} object(s) pushed to {xc_config.tenant_url}")


# ---------------------------------------------------------------------------
# xc-status (stub)
# ---------------------------------------------------------------------------


@app.command(name="xc-status")
def xc_status(
    tenant_url: Optional[str] = typer.Option(None, envvar="F5XC_TENANT_URL"),
    api_token: Optional[str] = typer.Option(None, envvar="F5XC_API_TOKEN"),
    p12_path: Optional[Path] = typer.Option(None, envvar="F5XC_P12_PATH"),
    p12_password: Optional[str] = typer.Option(None, envvar="F5XC_P12_PASSWORD"),
) -> None:
    """Check connectivity and status of an F5 XC tenant."""
    xc_config = _resolve_push_config(tenant_url, api_token, p12_path, p12_password)
    if xc_config is None:
        console.print("[yellow]No XC credentials configured.[/yellow]")
        console.print("Set F5XC_TENANT_URL + F5XC_API_TOKEN (env vars or --tenant-url/--api-token).")
        raise typer.Exit(code=1)

    from waffleiron.xc_client import XCClient

    client = XCClient(xc_config)

    console.print(f"Tenant: {xc_config.tenant_url}")
    console.print(f"Auth:   {xc_config.auth_method}")

    if client.check_connection():
        console.print("[green]Status: connected[/green]")

        namespaces = client.list_namespaces()
        ns_names = [ns["name"] for ns in namespaces[:10]]
        console.print(f"Namespaces: {', '.join(ns_names)}" + (" ..." if len(namespaces) > 10 else ""))
    else:
        console.print("[red]Status: connection failed[/red]")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_decisions_from_analysis(analysis: AnalysisResult) -> DecisionSet:
    """Build a DecisionSet with DEFER defaults from analysis alarm-only items."""
    ds = DecisionSet()

    for sig in analysis.alarm_only_signatures:
        ds.add_signature(
            SignatureDecision(
                sig_id=sig.sig_id,
                description=sig.description,
                scope=sig.scope,
                action=AlarmOnlyAction.DEFER,
            )
        )

    for viol in analysis.alarm_only_violations:
        ds.add_violation(
            ViolationDecision(
                violation=viol.violation_name,
                action=ViolationAction.DEFER,
            )
        )

    for gap in analysis.bot_gaps:
        ds.add_bot(
            BotDecision(
                category=gap.category,
                asm_action=gap.asm_action,
                action=BotDecisionAction.BLOCK,
            )
        )

    return ds
