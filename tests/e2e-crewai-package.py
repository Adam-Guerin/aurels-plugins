import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "plugins" / "aurels-integrations" / "integrations" / "crewai"


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


with tempfile.TemporaryDirectory(prefix="aurels-crewai-wheel-") as temporary:
    temp = Path(temporary)
    wheelhouse = temp / "wheelhouse"
    wheelhouse.mkdir()
    run(sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheelhouse), str(SOURCE))
    wheels = list(wheelhouse.glob("aurels_crewai-*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"Expected one Aurels CrewAI wheel, found {wheels}")

    environment = temp / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run(str(python), "-m", "pip", "install", "--no-deps", str(wheels[0]))
    run(
        str(python),
        "-c",
        "from aurel_crewai import AurelCrewAIConfig, AurelCrewAIGuard, AurelToolBlockedError, protect_tool; "
        "assert callable(protect_tool) and AurelCrewAIConfig and AurelCrewAIGuard and AurelToolBlockedError",
    )

print("CrewAI wheel builds, installs in a clean environment, and exposes its public API.")
