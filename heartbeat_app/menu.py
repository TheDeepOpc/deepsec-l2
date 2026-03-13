from getpass import getpass

from . import core
from .runtime import make_args, run_jwt_attack, run_pentest, run_recon_only, run_tool_status, run_websocket_test


def _ask_text(prompt: str, default: str = "", required: bool = False, secret: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        if secret:
            value = getpass(f"{prompt}{suffix}: ")
        else:
            value = input(f"{prompt}{suffix}: ").strip()
        if not value:
            value = default.strip() if isinstance(default, str) else default
        if value or not required:
            return value
        core.console.print("[red]This field is required.[/red]")


def _ask_bool(prompt: str, default: bool = False) -> bool:
    default_hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{default_hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "ha", "true", "1"}:
            return True
        if raw in {"n", "no", "yoq", "false", "0"}:
            return False
        core.console.print("[red]Please enter y or n.[/red]")


def _ask_choice(prompt: str, choices: list[str], default: str) -> str:
    mapping = {choice.lower(): choice for choice in choices}
    while True:
        raw = input(f"{prompt} {choices} [{default}]: ").strip().lower()
        if not raw:
            return default
        if raw in mapping:
            return mapping[raw]
        core.console.print(f"[red]Choose one of: {', '.join(choices)}[/red]")


def _print_header() -> None:
    core.console.print(core.BANNER)
    core.console.print("[cyan]Interactive Menu[/cyan]")
    core.console.print("  1. Pentest scan")
    core.console.print("  2. Recon only")
    core.console.print("  3. Show installed tools")
    core.console.print("  4. JWT attack")
    core.console.print("  5. WebSocket test")
    core.console.print("  6. Usage guide")
    core.console.print("  0. Exit")


def _print_usage() -> None:
    core.console.print("\n[bold]Menu usage[/bold]")
    core.console.print("  1. Pentest scan: full web test flow with optional login and advanced flags")
    core.console.print("  2. Recon only: detect HTTP targets, waf, open ports")
    core.console.print("  3. Show installed tools: verify nmap, ffuf, nuclei, sqlmap, etc.")
    core.console.print("  4. JWT attack: test a token directly")
    core.console.print("  5. WebSocket test: run ws:// or wss:// checks")
    core.console.print("\n[bold]Pentest prompts[/bold]")
    core.console.print("  target: URL/IP/domain")
    core.console.print("  authenticated?: if yes, menu asks login endpoint and credentials")
    core.console.print("  mode: full/web/api/spa/quick")
    core.console.print("  deep/ctf/oob/playwright: optional toggles")
    core.console.print("  output/model: optional runtime overrides")
    core.console.print("")


def _collect_common_runtime() -> tuple[str, str]:
    model = _ask_text("Override Ollama model", default="")
    output = _ask_text("Output directory", default="")
    return model, output


def _collect_pentest_args():
    core.console.print("\n[bold cyan]Pentest configuration[/bold cyan]")
    target = _ask_text("Target URL / IP / domain", required=True)
    mode = _ask_choice("Scan mode", ["full", "web", "api", "spa", "quick"], "full")
    ports = _ask_text("Specific ports (optional, e.g. 80,443,8080)", default="")
    authenticated = _ask_bool("Authenticated scan?", default=False)

    auth_url = ""
    user = ""
    password = ""
    admin_user = ""
    admin_pass = ""
    if authenticated:
        auth_url = _ask_text("Login endpoint path", default="/login", required=True)
        user = _ask_text("Username", required=True)
        password = _ask_text("Password", required=True, secret=True)
        if _ask_bool("Add admin credentials too?", default=False):
            admin_user = _ask_text("Admin username", required=True)
            admin_pass = _ask_text("Admin password", required=True, secret=True)

    deep = _ask_bool("Deep scan?", default=False)
    ctf = _ask_bool("CTF mode?", default=False)
    oob = _ask_bool("Enable OOB checks?", default=False)
    playwright = _ask_bool("Use Playwright crawl?", default=False)
    no_nuclei = _ask_bool("Skip Nuclei?", default=False)
    no_403 = _ask_bool("Skip recursive 403 bypass?", default=False)
    no_upload = _ask_bool("Skip file upload attack?", default=False)
    model, output = _collect_common_runtime()

    return make_args(
        target=target,
        auth_url=auth_url,
        user=user,
        password=password,
        admin_user=admin_user,
        admin_pass=admin_pass,
        mode=mode,
        deep=deep,
        ctf=ctf,
        oob=oob,
        playwright=playwright,
        no_nuclei=no_nuclei,
        no_403=no_403,
        no_upload=no_upload,
        ports=ports,
        model=model,
        output=output,
    )


def _run_menu_choice(choice: str) -> bool:
    if choice == "1":
        args = _collect_pentest_args()
        run_pentest(args)
        return True
    if choice == "2":
        target = _ask_text("Target URL / IP / domain", required=True)
        model, output = _collect_common_runtime()
        run_recon_only(target, model=model, output=output)
        return True
    if choice == "3":
        run_tool_status()
        return True
    if choice == "4":
        target = _ask_text("Target URL", required=True)
        jwt_token = _ask_text("JWT token", required=True)
        model, output = _collect_common_runtime()
        run_jwt_attack(target, jwt_token, model=model, output=output)
        return True
    if choice == "5":
        ws_url = _ask_text("WebSocket URL", required=True)
        model = _ask_text("Override Ollama model", default="")
        run_websocket_test(ws_url, model=model)
        return True
    if choice == "6":
        _print_usage()
        return True
    if choice == "0":
        core.console.print("[yellow]Exiting.[/yellow]")
        return False
    core.console.print("[red]Unknown menu choice.[/red]")
    return True


def run_main_menu() -> None:
    while True:
        _print_header()
        choice = input("\nSelect menu item: ").strip()
        try:
            keep_running = _run_menu_choice(choice)
        except KeyboardInterrupt:
            core.console.print("\n[yellow]Operation cancelled by user.[/yellow]")
            keep_running = True
        if not keep_running:
            break
        input("\nPress Enter to return to main menu...")
        core.console.print("")
