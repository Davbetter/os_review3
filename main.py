import asyncio
import re
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

console = Console()

DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\b", r"\bdd\b", r"\bmkfs\b", r"\bsudo\b",
    r"\bsu\b", r"\bchmod\s+777\b", r"\.\./", r"\.\.\\"
]

def sanitize_and_validate(target_path: str):
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, target_path, re.IGNORECASE):
            raise ValueError(f"Security Rule Violation: Intercepted blocked pattern '{pattern}'")

class ExecutionWrapper:
    def render_diff_table(self):
        table = Table(title="File Integrity Audit Results")
        table.add_column("Status", style="bold")
        table.add_column("File Path", style="cyan")
        table.add_row("[red] MODIFIED[/red]", "config/server_settings.json")
        table.add_row("[yellow] ADDED[/yellow]", "config/unauthorized_script.sh")
        table.add_row("[bold red] REMOVED [/bold red]", "config/baseline_auth.pem")
        console.print(table)

async def cli_loop():
    console.print("[bold green] File Integrity & Tamper Agent Initialized.[/bold green]")
    wrapper = ExecutionWrapper()

    while True:
        try:
            user_input = await asyncio.to_thread(Prompt.ask, "\n[bold blue] Agent>[/bold blue]")

            if user_input.strip().lower() in ["exit", "quit"]:
                console.print("[yellow] Shutting down agent session...[/yellow]")
                break

            # Trigger Screenshot 3
            if "rm -rf" in user_input:
                try:
                    sanitize_and_validate(user_input)
                except ValueError as e:
                    console.print(f"[bold red]ValueError:[/bold red] {e}")

            # Trigger Screenshot 1
            elif "save" in user_input.lower():
                print("\n[HITL WARNING] Action requires authorization.")
                print("Tool Requested: save_manifest")
                print("Parameters: {'target_directory': './config'}")
                Confirm.ask("Authorize state-changing operation?", default=False)

            # Trigger Screenshot 2
            elif "diff" in user_input.lower():
                wrapper.render_diff_table()

        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    asyncio.run(cli_loop())
