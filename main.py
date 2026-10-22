import argparse
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from agent import Agent
from guardrails import SecurityViolation, sanitize_and_validate

console = Console()
HERE = Path(__file__).resolve().parent

HELP = """Direct commands (no LLM needed):  list [dir] | hash [dir] | show [dir] | save [dir] | diff [dir] | exit
Anything else is sent to the LLM, e.g. "check my config folder for changes since the baseline"."""


# ------------------------------------------------------------ rendering
def render(name: str, data: dict) -> None:
    if name == "compare_diffs":
        if data["clean"]:
            console.print(f"[green]No changes.[/green] {data['unchanged_count']} file(s) match the baseline.")
            return
        t = Table(title="File Integrity Audit Results")
        t.add_column("Status", style="bold")
        t.add_column("File Path", style="cyan")
        for label, style, key in (("MODIFIED", "red", "modified"), ("ADDED", "yellow", "added"),
                                  ("REMOVED", "bold red", "removed")):
            for f in data[key]:
                t.add_row(Text(label, style=style), Text(f"{data['directory'].rstrip('/')}/{f}" if data["directory"] != "." else f))
        console.print(t)
        console.print(f"[dim]{data['unchanged_count']} file(s) unchanged.[/dim]")
    elif name == "list_directory":
        t = Table(title=f"Files in {data['directory']}")
        t.add_column("Path", style="cyan"); t.add_column("Size (B)", justify="right"); t.add_column("Modified (UTC)")
        for f in data["files"]:
            t.add_row(Text(f["path"]), str(f["size_bytes"]), f["modified_utc"])
        console.print(t)
    elif name == "hash_directory":
        t = Table(title=f"SHA-256 digests: {data['directory']}")
        t.add_column("Path", style="cyan"); t.add_column("SHA-256")
        for p, h in data["hashes"].items():
            t.add_row(Text(p), h)
        console.print(t)
    elif name == "read_json_state":
        console.print(f"[bold]Baseline[/bold] created {data['created_utc']} with {data['file_count']} file(s).")
    elif name == "write_snapshot":
        console.print(f"[green]Baseline saved:[/green] {data['file_count']} file(s) -> {data['manifest']}")


def hitl_confirm(name: str, args: dict) -> bool:
    print("\n[HITL WARNING] Action requires authorization.")
    print(f"Tool Requested: {name}")
    print(f"Parameters: {args}")
    return Confirm.ask("Authorize state-changing operation?", default=False)


# ------------------------------------------------------------ loop
async def run_direct(agent: Agent, cmd: str, arg: str) -> None:
    tool = {"list": "list_directory", "hash": "hash_directory", "show": "read_json_state",
            "save": "write_snapshot", "diff": "compare_diffs"}[cmd]
    out = await agent.call_tool(tool, {"path": arg})
    if out.ok and out.data is not None:
        render(tool, out.data)
    else:
        console.print(f"[bold red]Error:[/bold red] {out.text}")


async def cli_loop(agent: Agent, default_dir: str) -> None:
    console.print("[bold green]File Integrity & Tamper Agent Initialized.[/bold green]")
    console.print(f"[dim]Workspace: {agent.workspace}[/dim]\n[dim]{escape(HELP)}[/dim]")
    while True:
        try:
            line = await asyncio.to_thread(Prompt.ask, "\n[bold blue]Agent>[/bold blue]")
        except (KeyboardInterrupt, EOFError):
            break
        line = line.strip()
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            console.print("[yellow]Shutting down agent session...[/yellow]")
            break
        try:
            sanitize_and_validate(line)  # guardrail runs on EVERY input
            parts = line.split(maxsplit=1)
            if parts[0].lower() in ("list", "hash", "show", "save", "diff") and len(parts) <= 2:
                await run_direct(agent, parts[0].lower(), parts[1] if len(parts) > 1 else default_dir)
            else:
                await agent.ask(line)
        except SecurityViolation as e:
            console.print(f"[bold red]ValueError:[/bold red] {e}")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")


def make_llm(provider: str, model: str | None):
    if provider == "auto":
        provider = "anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "none"
    if provider == "anthropic":
        from llm import AnthropicLLM
        return AnthropicLLM(model)
    if provider == "ollama":
        from llm import OllamaLLM
        return OllamaLLM(model)
    return None


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", default=os.getcwd(), help="Directory the agent may touch (default: cwd)")
    ap.add_argument("--provider", choices=["auto", "anthropic", "ollama", "none"], default="auto")
    ap.add_argument("--model", default=None)
    a = ap.parse_args()

    ws = Path(a.workspace).resolve()
    default_dir = "config" if (ws / "config").is_dir() else "."
    params = StdioServerParameters(command=sys.executable, args=[str(HERE / "mcp_server.py")],
                                   env={**os.environ, "INTEGRITY_WORKSPACE": str(ws)}, cwd=str(HERE))
    async with stdio_client(params, errlog=open(os.devnull, "w")) as (r, w):  # hide server log noise
        async with ClientSession(r, w) as session:
            await session.initialize()
            llm = make_llm(a.provider, a.model)
            if llm is None:
                console.print("[yellow]No LLM configured: direct commands only.[/yellow]")
            agent = Agent(session, ws, hitl_confirm, llm,
                          on_tool=lambda n, args: console.print(f"[dim]-> {escape(n)}({escape(str(args))})[/dim]"),
                          on_text=lambda t: console.print(Markdown(t)))
            await cli_loop(agent, default_dir)


if __name__ == "__main__":
    asyncio.run(main())
