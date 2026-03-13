import signal
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

from . import core


DEFAULT_ARGS = {
    "target": "",
    "auth_url": "",
    "user": "",
    "password": "",
    "admin_user": "",
    "admin_pass": "",
    "mode": "full",
    "deep": False,
    "ctf": False,
    "oob": False,
    "playwright": False,
    "no_nuclei": False,
    "no_403": False,
    "no_upload": False,
    "intercept": False,
    "jwt": "",
    "ws": "",
    "ports": "",
    "recon_only": False,
    "tools": False,
    "output": "",
    "model": "",
}


def make_args(**overrides):
    data = dict(DEFAULT_ARGS)
    data.update(overrides)
    return SimpleNamespace(**data)


def apply_runtime_options(args) -> None:
    if getattr(args, "model", ""):
        core.MODEL_NAME = args.model
    output_dir = getattr(args, "output", "")
    if output_dir:
        core.REPORT_DIR = Path(output_dir)
        core.REPORT_DIR.mkdir(exist_ok=True, parents=True)


def run_pentest(args) -> Optional[list]:
    apply_runtime_options(args)
    pipeline = core.PentestPipeline(args)

    def _handle_sigint(signum, frame):
        core.console.print("\n[yellow]Interrupted — saving partial results...[/yellow]")
        pipeline.save_partial_results(reason="SIGINT")
        raise KeyboardInterrupt

    previous_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _handle_sigint)
    try:
        return pipeline.run()
    except KeyboardInterrupt:
        core.console.print("[yellow]Scan stopped by user.[/yellow]")
        return None
    except Exception as exc:
        core.console.print(f"[bold red]Unhandled error: {exc}[/bold red]")
        pipeline.save_partial_results(reason=f"exception: {type(exc).__name__}")
        raise
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def run_recon_only(target: str, model: str = "", output: str = ""):
    args = make_args(target=target, model=model, output=output)
    apply_runtime_options(args)
    ai = core.AIEngine()
    recon = core.ReconEngine(ai)
    result = recon.run(target)
    core.console.print("\n[bold]HTTP Targets found:[/bold]")
    for item in result.http_targets:
        core.console.print(f"  {item['url']}")
    return result


def run_tool_status() -> None:
    core._print_tools_status()


def run_jwt_attack(target: str, jwt_token: str, model: str = "", output: str = ""):
    args = make_args(target=target, model=model, output=output)
    apply_runtime_options(args)
    pipeline = core.PentestPipeline(args)
    attacker = core.JWTAttacker(pipeline.client, pipeline.oob)
    findings = attacker.attack(jwt_token, [{"url": target}])
    core.console.print(f"\n[bold]JWT Results:[/bold] {len(findings)} findings")
    for finding in findings:
        core.console.print(f"  [{finding.risk}] {finding.title}")
    return findings


def run_websocket_test(ws_url: str, model: str = ""):
    args = make_args(model=model)
    apply_runtime_options(args)
    tester = core.WebSocketTester(core.AIEngine())
    findings = tester.test(ws_url)
    core.console.print(f"\n[bold]WebSocket Results:[/bold] {len(findings)} findings")
    for finding in findings:
        core.console.print(f"  [{finding.risk}] {finding.title}")
    return findings
