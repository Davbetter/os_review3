"""Orchestration layer: guardrails -> HITL -> MCP call -> feedback to the LLM."""
import json
from dataclasses import dataclass
from pathlib import Path

from guardrails import SecurityViolation, resolve_in_workspace, sanitize_and_validate

STATE_CHANGING = {"write_snapshot"}
MAX_STEPS = 8


@dataclass
class Outcome:
    ok: bool
    text: str
    data: dict | None = None


class Agent:
    def __init__(self, session, workspace: Path, confirm, llm=None, on_tool=None, on_text=None):
        self.session = session
        self.workspace = workspace
        self.confirm = confirm      # (tool_name, args) -> bool
        self.llm = llm
        self.on_tool = on_tool or (lambda name, args: None)
        self.on_text = on_text or (lambda text: None)
        self.history: list[dict] = []   # persists across turns so chained checks keep context
        self._tools = None

    async def tool_specs(self):
        if self._tools is None:
            listed = await self.session.list_tools()
            self._tools = [{"name": t.name, "description": t.description or "", "schema": t.inputSchema}
                           for t in listed.tools]
        return self._tools

    async def call_tool(self, name: str, args: dict) -> Outcome:
        """Every tool call (from the LLM or a direct command) passes through the same gates."""
        try:
            for v in args.values():
                if isinstance(v, str):
                    sanitize_and_validate(v)
            if "path" in args:
                resolve_in_workspace(str(args["path"]), self.workspace)
        except SecurityViolation as e:
            return Outcome(False, str(e))

        if name in STATE_CHANGING and not self.confirm(name, args):
            return Outcome(False, "Operator declined the state-changing operation. Nothing was written.")

        self.on_tool(name, args)
        try:
            result = await self.session.call_tool(name, args)
        except Exception as e:  # protocol / validation errors
            return Outcome(False, f"Tool call failed: {e}")
        text = "".join(getattr(c, "text", "") for c in result.content)
        if result.isError:
            return Outcome(False, text)
        try:
            return Outcome(True, text, json.loads(text))
        except json.JSONDecodeError:
            return Outcome(True, text)

    async def ask(self, user_text: str) -> None:
        """Natural-language turn: LLM chooses tools, system executes, results feed back."""
        sanitize_and_validate(user_text)          # raises SecurityViolation before the LLM sees it
        if self.llm is None:
            raise RuntimeError("No LLM configured (set ANTHROPIC_API_KEY or use --provider ollama).")
        specs = await self.tool_specs()
        self.history.append({"role": "user", "text": user_text})
        for _ in range(MAX_STEPS):
            reply = self.llm.step(self.history, specs)
            self.history.append({"role": "assistant", "text": reply.text, "calls": reply.calls})
            if not reply.calls:
                self.on_text(reply.text)
                return
            for call in reply.calls:
                outcome = await self.call_tool(call["name"], call["args"])
                self.history.append({"role": "tool", "id": call["id"], "name": call["name"],
                                     "content": outcome.text, "is_error": not outcome.ok})
        self.on_text("Stopped: reached the maximum number of tool steps for one request.")
