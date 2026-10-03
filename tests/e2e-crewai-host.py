"""Real CrewAI BaseTool.run dispatch with synthetic policy decisions only."""
import os
os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["CREWAI_TELEMETRY_DISABLED"] = "true"

import sys
import asyncio
from pathlib import Path
from typing import Type
from pydantic import BaseModel, Field, PrivateAttr
from crewai.tools import BaseTool

if os.getenv("AURELS_CREWAI_USE_INSTALLED") != "1":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins/aurels-integrations/integrations/crewai"))
from aurel_crewai import AurelCrewAIConfig, AurelCrewAIGuard, AurelToolBlockedError, protect_tool


class Arguments(BaseModel):
    path: str = Field(description="Synthetic fixture path")


class ReadFixture(BaseTool):
    name: str = "read_fixture"
    description: str = "Synthetic fixture; no real files are read"
    args_schema: Type[BaseModel] = Arguments
    _dispatched: list = PrivateAttr(default_factory=list)

    def _run(self, path: str):
        self._dispatched.append(path)
        return f"read:{path}"

    async def _arun(self, path: str):
        self._dispatched.append(path)
        return f"read:{path}"


class Policy(AurelCrewAIGuard):
    def __init__(self, decision, approval=None):
        super().__init__(AurelCrewAIConfig(telemetry_enabled=False, approval_handler=approval))
        self.decision = decision

    def _post_json(self, path, payload):
        if self.decision == "outage":
            raise TimeoutError("Synthetic outage")
        return {"decision": self.decision, **({"rewrittenArguments": {"path": "rewritten.txt"}} if self.decision == "rewrite" else {})}


for decision, approval, expected in [("allow", None, ["original.txt"]), ("block", None, []),
    ("require_approval", None, []), ("require_approval", lambda *_: False, []),
    ("require_approval", lambda *_: True, ["original.txt"]), ("rewrite", None, ["rewritten.txt"]), ("outage", None, [])]:
    original = ReadFixture()
    protected = protect_tool(original, Policy(decision, approval))
    assert isinstance(protected, BaseTool)
    try:
        result = protected.run(path="original.txt")
        assert expected and result == f"read:{expected[0]}", (decision, result)
    except AurelToolBlockedError:
        assert not expected, decision
    assert original._dispatched == expected, (decision, original._dispatched, expected)
    print(f"PASS CrewAI native BaseTool.run: {decision}, dispatched={len(expected)}")
    async_original = ReadFixture()
    async_protected = protect_tool(async_original, Policy(decision, approval))
    try:
        result = asyncio.run(async_protected.arun(path="original.txt"))
        assert expected and result == f"read:{expected[0]}", (decision, result)
    except AurelToolBlockedError:
        assert not expected, decision
    assert async_original._dispatched == expected, (decision, async_original._dispatched, expected)
    print(f"PASS CrewAI native BaseTool.arun: {decision}, dispatched={len(expected)}")
