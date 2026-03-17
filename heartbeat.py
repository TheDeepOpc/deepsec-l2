#!/usr/bin/env python3
import argparse
import datetime

from heartbeat_app import core
from heartbeat_app.menu import run_main_menu
from heartbeat_app.runtime import make_args, run_pentest
from heartbeat_app.modules.reporting import Reporter
from heartbeat_app.modules.ai import AIEngine
from heartbeat_app.modules.http_session import EndpointGraph
from heartbeat_app.modules.recon import ReconEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DeepSec launcher")
    parser.add_argument("--target", default="", help="Target URL/IP/domain")
    parser.add_argument("--auth-url", default="", help="Login URL or path")
    parser.add_argument("--user", default="", help="Username")
    parser.add_argument("--pass", "--password", dest="password", default="", help="Password")
    parser.add_argument("--admin-user", default="", help="Admin username")
    parser.add_argument("--admin-pass", default="", help="Admin password")
    parser.add_argument("--mode", default="full", choices=["full", "web", "api", "spa", "quick"], help="Scan mode")
    parser.add_argument("--deep", action="store_true", help="Enable deep scan")
    parser.add_argument("--ctf", action="store_true", help="Enable CTF mode")
    parser.add_argument("--oob", action="store_true", help="Enable OOB checks")
    parser.add_argument("--playwright", action="store_true", help="Enable Playwright crawl")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei")
    parser.add_argument("--no-403", action="store_true", help="Skip recursive 403 checks")
    parser.add_argument("--no-upload", action="store_true", help="Skip upload attacks")
    parser.add_argument("--intercept", action="store_true", help="Enable mitmproxy interceptor")
    parser.add_argument("--ports", default="", help="Specific ports (e.g. 80,443,8080)")
    parser.add_argument("--model", default="", help="Override Ollama model")
    parser.add_argument("--output", default="", help="Custom output directory")
    parser.add_argument("--generate-docx-report", action="store_true", help="Generate a DOCX report")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Backward-compatible behavior:
    # - If no --target provided -> interactive menu.
    # - If --target provided -> run one-shot CLI scan.
    if not args.target:
        run_main_menu()
        return

    runtime_args = make_args(
        target=args.target,
        auth_url=args.auth_url,
        user=args.user,
        password=args.password,
        admin_user=args.admin_user,
        admin_pass=args.admin_pass,
        mode=args.mode,
        deep=args.deep,
        ctf=args.ctf,
        oob=args.oob,
        playwright=args.playwright,
        no_nuclei=args.no_nuclei,
        no_403=args.no_403,
        no_upload=args.no_upload,
        intercept=args.intercept,
        ports=args.ports,
        model=args.model,
        output=args.output,
    )
    findings = run_pentest(runtime_args)

    if args.generate_docx_report and findings is not None:
        tech_stack = {}
        try:
            tech_stack = ReconEngine(AIEngine()).run(runtime_args.target).tech_stack
        except Exception as exc:
            core.console.print(f"[yellow]DOCX tech fingerprint skipped: {exc}[/yellow]")

        reporter = Reporter(runtime_args.target, EndpointGraph())

        report_filename = f"pentest_report_{runtime_args.target.replace('http://', '').replace('https://', '').replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        output_path = (core.REPORT_DIR / report_filename).as_posix()

        print(f"\n[bold green]Generating DOCX report to {output_path}...[/bold green]")
        reporter.generate_docx_report(findings, tech_stack, output_path)


if __name__ == "__main__":
    main()
